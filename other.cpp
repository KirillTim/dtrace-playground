/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Trimmed down by Remigiusz 'lRem' Modrzejewski as part of TclDtrace
 * See http://dev.lrem.net/tcldtrace/ for information about TclDtrace.
 */

#pragma ident	"@(#)dtrace.c	1.25	06/09/19 SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dtrace.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <alloca.h>
#include <libproc.h>

#ifdef __APPLE__
#include <mach-o/arch.h>
#include <mach/machine.h>
#include <getopt.h>
#include <iostream>

#endif

typedef struct dtrace_cmd {
    char *dc_arg;				/* argument from main argv */
    const char *dc_name;			/* name for error messages */
    const char *dc_desc;			/* desc for error messages */
    dtrace_prog_t *dc_prog;			/* program compiled from arg */
    char dc_ofile[PATH_MAX];		/* derived output file name */
} dtrace_cmd_t;

#define	DMODE_VERS	0	/* display version information and exit (-V) */
#define	DMODE_EXEC	1	/* compile program for enabling (-a/e/E) */
#define	DMODE_ANON	2	/* compile program for anonymous tracing (-A) */
#define	DMODE_LINK	3	/* compile program for linking with ELF (-G) */
#define	DMODE_LIST	4	/* compile program and list probes (-l) */
#define	DMODE_HEADER	5	/* compile program for headergen (-h) */

#define	E_SUCCESS	0
#define	E_ERROR		1
#define	E_USAGE		2

static const char DTRACE_OPTSTR[] =
        "Fp:qs:";

static char **g_argv;
static int g_argc;
static char **g_objv;
static int g_objc;
static dtrace_cmd_t *g_cmdv;
static int g_cmdc;
static struct ps_prochandle **g_psv;
static int g_psc;
static int g_pslive;
static int g_quiet;
static int g_flowindent;
static int g_intr;
static int g_impatient;
static int g_newline;
static int g_total;
static int g_cflags;
static int g_oflags;
static int g_mode = DMODE_EXEC;
static int g_status = E_SUCCESS;
static int g_grabanon = 0;
static const char *g_ofile = NULL;
static dtrace_hdl_t *g_dtp;
static char *g_etcfile = "/etc/system";
static const char *g_etcbegin = "* vvvv Added by DTrace";
static const char *g_etcend = "* ^^^^ Added by DTrace";

static const char *g_etc[] =  {
        "*",
        "* The following forceload directives were added by dtrace(1M) to allow for",
        "* tracing during boot.  If these directives are removed, the system will",
        "* continue to function, but tracing will not occur during boot as desired.",
        "* To remove these directives (and this block comment) automatically, run",
        "* \"dtrace -A\" without additional arguments.  See the \"Anonymous Tracing\"",
        "* chapter of the Solaris Dynamic Tracing Guide for details.",
        "*",
        NULL };

static void
verror(const char *fmt, va_list ap)
{
    int error = errno;

    (void) fprintf(stderr, "dtrace: ");
    (void) vfprintf(stderr, fmt, ap);

    if (fmt[strlen(fmt) - 1] != '\n')
        (void) fprintf(stderr, ": %s\n", strerror(error));
}

/*PRINTFLIKE1*/
static void
fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verror(fmt, ap);
    va_end(ap);

    exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
dfatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "dtrace: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, ": %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));

#ifndef __APPLE__
    /*
	 * Close the DTrace handle to ensure that any controlled processes are
	 * correctly restored and continued.
	 */
	dtrace_close(g_dtp);
#else
    if (g_dtp) {
        int i;
        for (i = 0; i < g_psc; i++) {
            dtrace_proc_continue(g_dtp, g_psv[i]);
            dtrace_proc_release(g_dtp, g_psv[i]);
        }
    }
#endif

    exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verror(fmt, ap);
    va_end(ap);
}

/*PRINTFLIKE1*/
static void
notice(const char *fmt, ...)
{
    va_list ap;

    if (g_quiet)
        return; /* -q or quiet pragma suppresses notice()s */

    va_start(ap, fmt);
    verror(fmt, ap);
    va_end(ap);
}

/*
 * Execute the specified program by enabling the corresponding instrumentation.
 * If -e has been specified, we get the program info but do not enable it.  If
 * -v has been specified, we print a stability report for the program.
 */
static void
exec_prog(const dtrace_cmd_t *dcp)
{
    dtrace_ecbdesc_t *last = NULL;
    dtrace_proginfo_t dpi;

    if (dtrace_program_exec(g_dtp, dcp->dc_prog, &dpi) == -1) {
        dfatal("failed to enable '%s'", dcp->dc_name);
    } else {
        notice("%s '%s' matched %u probe%s\n",
               dcp->dc_desc, dcp->dc_name,
               dpi.dpi_matches, dpi.dpi_matches == 1 ? "" : "s");
    }

    g_total += dpi.dpi_matches;
}

/*static void
compile_string(dtrace_cmd_t *dcp, const char* g_prog)
{
    char* arg0 = g_argv[0];
    g_argv[0] = dcp->dc_arg;

    if ((dcp->dc_prog = dtrace_program_strcompile(g_dtp, g_prog, DTRACE_PROBESPEC_NAME, g_cflags, g_argc, g_argv))
        == NULL)
        dfatal("failed to compile script %s", dcp->dc_arg);

    g_argv[0] = arg0;

    dcp->dc_desc = "script";
    dcp->dc_name = dcp->dc_arg;
}*/

static void
compile_file(dtrace_cmd_t *dcp)
{
    char *arg0;
    FILE *fp;

    if ((fp = fopen(dcp->dc_arg, "r")) == NULL)
        fatal("failed to open %s", dcp->dc_arg);

    arg0 = g_argv[0];
    g_argv[0] = dcp->dc_arg;

    if ((dcp->dc_prog = dtrace_program_fcompile(g_dtp, fp,
                                                g_cflags, g_argc, g_argv)) == NULL)
        dfatal("failed to compile script %s", dcp->dc_arg);

    g_argv[0] = arg0;
    (void) fclose(fp);

    dcp->dc_desc = "script";
    dcp->dc_name = dcp->dc_arg;
}

/*ARGSUSED*/
static void
prochandler(struct ps_prochandle *P, const char *msg, void *arg)
{
#ifndef __APPLE__
    const psinfo_t *prp = Ppsinfo(P);
	int pid = Pstatus(P)->pr_pid;
#else
#define SIG2STR_MAX 32
#define proc_signame(x,y,z) "Unknown"
    /*typedef struct psinfo { int pr_wstat; } psinfo_t;
    const psinfo_t *prp = NULL;
    int pid = Pstatus(P)->pr_pid;*/
    int pid = -1;
#endif
    char name[SIG2STR_MAX];

    if (msg != NULL) {
        notice("pid %d: %s\n", pid, msg);
        return;
    }

//    switch (Pstate(P)) {
//        case PS_UNDEAD:
//            /*
//             * Ideally we would like to always report pr_wstat here, but it
//             * isn't possible given current /proc semantics.  If we grabbed
//             * the process, Ppsinfo() will either fail or return a zeroed
//             * psinfo_t depending on how far the parent is in reaping it.
//             * When /proc provides a stable pr_wstat in the status file,
//             * this code can be improved by examining this new pr_wstat.
//             */
//            if (prp != NULL && WIFSIGNALED(prp->pr_wstat)) {
//                notice("pid %d terminated by %s\n", pid,
//                       proc_signame(WTERMSIG(prp->pr_wstat),
//                                    name, sizeof (name)));
//            } else if (prp != NULL && WEXITSTATUS(prp->pr_wstat) != 0) {
//                notice("pid %d exited with status %d\n",
//                       pid, WEXITSTATUS(prp->pr_wstat));
//            } else {
//                notice("pid %d has exited\n", pid);
//            }
//            g_pslive--;
//            break;
//
//        case PS_LOST:
//            notice("pid %d has exited or exec'd a set-id or unobservable program\n", pid);
//            g_pslive--;
//            break;
//    }
}

/*ARGSUSED*/
static int
errhandler(const dtrace_errdata_t *data, void *arg)
{
    error(data->dteda_msg);
    return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
drophandler(const dtrace_dropdata_t *data, void *arg)
{
    error(data->dtdda_msg);
    return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
setopthandler(const dtrace_setoptdata_t *data, void *arg)
{
    if (strcmp(data->dtsda_option, "quiet") == 0)
        g_quiet = data->dtsda_newval != DTRACEOPT_UNSET;

    if (strcmp(data->dtsda_option, "flowindent") == 0)
        g_flowindent = data->dtsda_newval != DTRACEOPT_UNSET;

    return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
    printf("\nGOT A BUFFER: \n");

    if(bufdata->dtbda_aggdata)
    {
        printf("It's a part of an aggregation\n");
        printf("%s %s", bufdata->dtbda_aggdata->dtada_desc->dtagd_name, bufdata->dtbda_buffered);
        return (DTRACE_HANDLE_OK);
    }

    printf("Type: ");
    switch(bufdata->dtbda_recdesc->dtrd_action)
    {
        case DTRACEACT_DIFEXPR:
            printf("It's a trace()\n");
            break;
        case DTRACEACT_PRINTF:
            printf("It's a printf()\n");
            break;
        case DTRACEACT_STACK:
        case DTRACEACT_USTACK:
        case DTRACEACT_JSTACK:
            printf("It's some kind of a stack\n");
            printf("We could try to parse it...\n");
            break;
        default:
            printf("It's some kond of a something.");
    }

    printf("%s", bufdata->dtbda_buffered);
    return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
    dtrace_actkind_t act;
    uintptr_t addr;

    if (rec == NULL) {
        /*
         * We have processed the final record; output the newline if
         * we're not in quiet mode.
         */
        if (!g_quiet)
            printf("\n");

        return (DTRACE_CONSUME_NEXT);
    }

    act = rec->dtrd_action;
    addr = (uintptr_t)data->dtpda_data;

    if (act == DTRACEACT_EXIT) {
        g_status = *((uint32_t *)addr);
        return (DTRACE_CONSUME_NEXT);
    }

    return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{
    dtrace_probedesc_t *pd = data->dtpda_pdesc;
    processorid_t cpu = data->dtpda_cpu;
    static int heading;

    if (g_impatient) {
        g_newline = 0;
        return (DTRACE_CONSUME_ABORT);
    }

    if (heading == 0) {
        if (!g_flowindent) {
            if (!g_quiet) {
                printf("%3s %6s %32s\n",
                       "CPU", "ID", "FUNCTION:NAME");
            }
        } else {
            printf("%3s %-41s\n", "CPU", "FUNCTION");
        }
        heading = 1;
    }

    if (!g_flowindent) {
        if (!g_quiet) {
            char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];

            (void) snprintf(name, sizeof (name), "%s:%s",
                            pd->dtpd_func, pd->dtpd_name);

            printf("%3d %6d %32s ", cpu, pd->dtpd_id, name);
        }
    } else {
        int indent = data->dtpda_indent;
        char *name;
        size_t len;

        if (data->dtpda_flow == DTRACEFLOW_NONE) {
            len = indent + DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 5;
            name = (char*)alloca(len);
            (void) snprintf(name, len, "%*s%s%s:%s", indent, "",
                            data->dtpda_prefix, pd->dtpd_func,
                            pd->dtpd_name);
        } else {
            len = indent + DTRACE_FUNCNAMELEN + 5;
            name = (char*)alloca(len);
            (void) snprintf(name, len, "%*s%s%s", indent, "",
                            data->dtpda_prefix, pd->dtpd_func);
        }

        printf("%3d %-41s ", cpu, name);
    }

    return (DTRACE_CONSUME_THIS);
}


/*ARGSUSED*/
static void
intr(int signo)
{
    if (!g_intr)
        g_newline = 1;

    if (g_intr++)
        g_impatient = 1;
}

int
main(int argc, char *argv[])
{
    dtrace_bufdesc_t buf;
    struct sigaction act, oact;
    dtrace_status_t status[2];
    dtrace_optval_t opt;

    int done = 0, mode = 0;
    int err, i;
    char c, *p, **v;
    struct ps_prochandle *P;
    pid_t pid;

    if (argc == 1)
        return 1;

    if ((g_argv = static_cast<char **>(malloc(sizeof (char *) * argc))) == NULL ||
        (g_cmdv = static_cast<dtrace_cmd_t *>(malloc(sizeof (dtrace_cmd_t) * argc))) == NULL ||
        (g_psv = static_cast<ps_prochandle **>(malloc(sizeof (struct ps_prochandle *) * argc))) == NULL)
        fatal("failed to allocate memory for arguments");

    g_argv[g_argc++] = argv[0];	/* propagate argv[0] to D as $0/$$0 */

    bzero(status, sizeof (status));
    bzero(&buf, sizeof (buf));

    /*
     * Open libdtrace.
     */
    if ((g_dtp = dtrace_open(DTRACE_VERSION, g_oflags, &err)) == NULL) {
        fatal("failed to initialize dtrace: %s\n",
              dtrace_errmsg(NULL, err));
    }

    (void) dtrace_setopt(g_dtp, "bufsize", "4m");
    (void) dtrace_setopt(g_dtp, "aggsize", "4m");

    /*
     * Set those few options we support. Note grabbing script names into g_cmdv.
     */
    for (optind = 1; optind < argc; optind++) {
        while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != EOF) {
            switch (c) {

                case 'F':
                    if (dtrace_setopt(g_dtp, "flowindent", 0) != 0)
                        dfatal("failed to set -F");
                    break;

                case 'q':
                    if (dtrace_setopt(g_dtp, "quiet", 0) != 0)
                        dfatal("failed to set -q");
                    break;

                case 's':
                    g_cmdv[g_cmdc++].dc_arg = optarg;
                    break;

                case 'p':
                    errno = 0;
                    pid = strtol(optarg, &p, 10);
                    using namespace std;
                    cerr << "pid = " << pid << endl;

                    if (errno != 0 || p == optarg || p[0] != '\0')
                        fatal("invalid pid: %s\n", optarg);

                    P = dtrace_proc_grab(g_dtp, pid, 0);
                    if (P == NULL)
                        dfatal("");

                    g_psv[g_psc++] = P;
                    break;

                default:
                    return 1;
            }
        }
    }

/*#ifdef __APPLE__
    if(host_arch & CPU_ARCH_ABI64) {
        g_oflags &= ~DTRACE_O_ILP32;
        g_oflags |= DTRACE_O_LP64;
    }
    else {
        g_oflags &= ~DTRACE_O_LP64;
        g_oflags |= DTRACE_O_ILP32;
    }

    dtrace_setopt(g_dtp, "stacksymbols", "enabled");
    dtrace_setopt(g_dtp, "arch", string_for_arch(host_arch));
#endif */

    // Dtrace Callbacks
    if (dtrace_handle_err(g_dtp, &errhandler, NULL) == -1)
        dfatal("failed to establish error handler");

    if (dtrace_handle_drop(g_dtp, &drophandler, NULL) == -1)
        dfatal("failed to establish drop handler");

    if (dtrace_handle_proc(g_dtp, &prochandler, NULL) == -1)
        dfatal("failed to establish proc handler");

    if (dtrace_handle_setopt(g_dtp, &setopthandler, NULL) == -1)
        dfatal("failed to establish setopt handler");

    if (dtrace_handle_buffered(g_dtp, &bufhandler, NULL) == -1)
        dfatal("failed to establish buffered handler");

    /*
     * Compile all the programs.
     */
    for (i = 0; i < g_cmdc; i++)
        compile_file(&g_cmdv[i]);

    // In case something changed these while we were not watching
    dtrace_getopt(g_dtp, "flowindent", &opt);
    g_flowindent = opt != DTRACEOPT_UNSET;

    dtrace_getopt(g_dtp, "quiet", &opt);
    g_quiet = opt != DTRACEOPT_UNSET;

    /*
     * Execute the programs.
     */

    for (i = 0; i < g_cmdc; i++)
        exec_prog(&g_cmdv[i]);


    /*
     * If -a and -Z were not specified and no probes have been matched, no
     * probe criteria was specified on the command line and we abort.
     */
    if (g_total == 0 && !g_grabanon && !(g_cflags & DTRACE_C_ZDEFS))
        dfatal("no probes %s\n", g_cmdc ? "matched" : "specified");


    /* This can shrink buffers and reduce/increase rates.
     * Originally it was wrapped just for checking that.
     * As we don't consume annonymous state, we don't need it.
     */
    if (dtrace_go(g_dtp) == -1)
        dfatal("could not enable tracing");

    (void) sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = intr;

    if (sigaction(SIGINT, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
        (void) sigaction(SIGINT, &act, NULL);

    if (sigaction(SIGTERM, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
        (void) sigaction(SIGTERM, &act, NULL);

    /*
     * Now that tracing is active and we are ready to consume trace data,
     * continue any grabbed or created processes, setting them running
     * using the /proc control mechanism inside of libdtrace.
     */
    for (i = 0; i < g_psc; i++)
        dtrace_proc_continue(g_dtp, g_psv[i]);

    g_pslive = g_psc; /* count for prochandler() */

    /*
     * The tracing loop. Beware.
     */
    do {
        if (!g_intr && !done)
            dtrace_sleep(g_dtp);

        if (g_newline) {
            /*
             * Output a newline just to make the output look
             * slightly cleaner.  Note that we do this even in
             * "quiet" mode...
             */
            printf("\n");
            g_newline = 0;
        }

        if (done || g_intr || (g_psc != 0 && g_pslive == 0)) {
            done = 1;
            if (dtrace_stop(g_dtp) == -1)
                dfatal("couldn't stop tracing");
        }

        switch (dtrace_work(g_dtp, NULL, chew, chewrec, NULL)) {
            case DTRACE_WORKSTATUS_DONE:
                done = 1;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                break;
            default:
                if (!g_impatient && dtrace_errno(g_dtp) != EINTR)
                    dfatal("processing aborted");
        }

        if (fflush(stdout) == EOF)
            clearerr(stdout);
    } while (!done);

    printf("\n");

    if (!g_impatient) {
        if (dtrace_aggregate_print(g_dtp, stdout, NULL) == -1 &&
            dtrace_errno(g_dtp) != EINTR)
            dfatal("failed to print aggregations");
    }

    dtrace_close(g_dtp);
    return (g_status);
}