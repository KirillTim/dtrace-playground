#include <iostream>

#include <unistd.h>

#include <dtrace.h>
#include <csignal>

using namespace std;

static dtrace_hdl_t *g_dtp;

static void print_pid_and_tid(const string &prefix = "") {
    uint64_t tid;
    pthread_threadid_np(nullptr, &tid);
    cout << prefix << " pid = " << getpid() << " tid = " << tid << endl;
};

static int bufhandler_counter = 0;

static void print_dtrace_probedata(const dtrace_probedata_t *data) {
    /*printf("dtrace_probedata_t addr = %p\n", data);
    dtrace_probedesc_t *pd = data->dtpda_pdesc;
    processorid_t cpu = data->dtpda_cpu;
    string full_probe_name = string(pd->dtpd_provider) + " " + string(pd->dtpd_mod) + " " + string(pd->dtpd_func)
                             + " " + string(pd->dtpd_name);*/
    //string raw = string((const char*)data->dtpda_data);
    //cout << "on cpu: " << cpu << " " << full_probe_name << " raw: " << raw <<"\n---\nlength() = "<< raw.length() <<"\n";
}

static int chew(const dtrace_probedata_t *data, void *arg) {
    print_pid_and_tid("chew()");

    //print_dtrace_probedata(data);

    /*dtrace_probedesc_t *pd = data->dtpda_pdesc;
    processorid_t cpu = data->dtpda_cpu;
    char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];
    (void) snprintf(name, sizeof(name), "%s:%s", pd->dtpd_func, pd->dtpd_name);
    printf("chew dtrace event: %3d %6d %32s \n", cpu, pd->dtpd_id, name);*/
    return (DTRACE_CONSUME_THIS);
}

static int chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg) {
    print_pid_and_tid("chewrec()");
    //print_dtrace_probedata(data);
    // A NULL rec indicates that we've processed the last record.
    if (rec == nullptr) {
        return (DTRACE_CONSUME_NEXT);
    }
    dtrace_actkind_t act = rec->dtrd_action;
    //cout << "act == " << act << endl;
    if (act == DTRACEACT_EXIT) {
        return (DTRACE_CONSUME_NEXT);
    }
    return (DTRACE_CONSUME_THIS);
}

static void verror(const char *fmt, va_list ap) {
    int error = errno;

    (void) fprintf(stderr, "dtrace: ");
    (void) vfprintf(stderr, fmt, ap);

    if (fmt[strlen(fmt) - 1] != '\n')
        (void) fprintf(stderr, ": %s\n", strerror(error));
}

/*PRINTFLIKE1*/
static void error(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    verror(fmt, ap);
    va_end(ap);
}

static int errhandler(const dtrace_errdata_t *data, void *arg) {
    error(data->dteda_msg);
    return (DTRACE_HANDLE_OK);
}

static int bufhandler(const dtrace_bufdata_t *bufdata, void *arg) {
    cout << "bufhandler " << bufhandler_counter ++ << " \n";
    //printf("bufhandler dtrace_bufdata_t addr = %p\n", bufdata);
    //printf("bufdata->dtbda_buffered = %p\n", (void*)bufdata->dtbda_buffered);
    //print_pid_and_tid("bufhandler()");

    //print_dtrace_probedata(bufdata->dtbda_probe);

    if (bufdata->dtbda_aggdata) {
        printf("It's a part of an aggregation\n");
        printf("%s %s", bufdata->dtbda_aggdata->dtada_desc->dtagd_name, bufdata->dtbda_buffered);
        return (DTRACE_HANDLE_OK);
    }

    printf("Type: ");
    //int x = bufdata->dtbda_buffered;
    switch (bufdata->dtbda_recdesc->dtrd_action) {
        case DTRACEACT_DIFEXPR:
            printf("It's a trace()\n");
            break;
        case DTRACEACT_PRINTF:
            printf("It's a printf()\n");
            break;
        case DTRACEACT_STACK:
            printf("It's a stack()\n");
            break;
        case DTRACEACT_USTACK:
            printf("It's a ustack()\n");
            break;
        default:
            printf("It's some kond of a something.\n");
    }
    //string data = string(bufdata->dtbda_buffered);
    printf("%s\n", bufdata->dtbda_buffered);
    return (DTRACE_HANDLE_OK);
}

//static const char *g_prog = R"(BEGIN { printf("hello from dtrace\n"); ustack(); }  profile-333 {ustack(10);})";
static const char *g_prog = R"(BEGIN { printf("hello from dtrace\n"); stack(); ustack(); }  END {ustack(10);})";
//static const char* g_prog = "syscall::open*:entry { printf(\"%s %s\\n\", execname, copyinstr(arg0)); }";

static int g_intr;
static int g_exited;

static void intr(int signo) {
    g_intr = 1;
}

static struct ps_prochandle *target_process;

static void dfatal(const char *fmt, ...) {
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
        dtrace_proc_continue(g_dtp, target_process);
        dtrace_proc_release(g_dtp, target_process);
    }
#endif
    exit(1);
}

int main(int argc, char **argv) {
    //printf("%s %x", "foo",12);
    //return 0;
    //int target_pid = stoi(argv[1]);
    //print_pid_and_tid("main(target_pid = " + string(argv[1]) + ")");
    print_pid_and_tid("main()");
    int err;

    if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == nullptr) {
        fprintf(stderr, "failed to initialize dtrace: %s\n", dtrace_errmsg(nullptr, err));
        return -1;
    }
    printf("Dtrace initialized\n");

    (void) dtrace_setopt(g_dtp, "bufsize", "4m");
    (void) dtrace_setopt(g_dtp, "aggsize", "4m");
    printf("dtrace options set\n");

    //dtrace_proc_grab(g_dtp, target_pid, 0);

    if (dtrace_handle_err(g_dtp, &errhandler, nullptr) == -1)
        dfatal("failed to establish error handler");

    if (dtrace_handle_buffered(g_dtp, &bufhandler, nullptr) == -1)
        dfatal("failed to establish buffered handler");

    dtrace_prog_t *prog;
    if ((prog = dtrace_program_strcompile(g_dtp, g_prog, DTRACE_PROBESPEC_NAME, 0, 0, nullptr)) == nullptr) {
        fprintf(stderr, "failed to compile dtrace program\n");
        return -1;
    } else {
        printf("dtrace program compiled\n");
    }

    dtrace_proginfo_t info{};
    if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
        fprintf(stderr, "failed to enable dtrace probes\n");
        return -1;
    } else {
        printf("dtrace probes enabled\n");
    }

    /*struct sigaction act{};
    (void) sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = intr;
    (void) sigaction(SIGINT, &act, nullptr);
    (void) sigaction(SIGTERM, &act, nullptr);*/

    if (dtrace_go(g_dtp) != 0) {
        fprintf(stderr, "could not start instrumentation\n");
        return -1;
    } else {
        printf("instrumentation started ..\n");
    }

    int done = 0;
    do {
        if (!g_intr && !done) {
            dtrace_sleep(g_dtp);
        }

        if (done || g_intr || g_exited) {
            done = 1;
            if (dtrace_stop(g_dtp) == -1) {
                fprintf(stderr, "could not stop tracing\n");
                return -1;
            }
        }

        switch (dtrace_work(g_dtp, /*stdout*/nullptr, chew, chewrec, nullptr)) {
            case DTRACE_WORKSTATUS_DONE:
                done = 1;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                break;
            default:
                fprintf(stderr, "processing aborted");
                return -1;
        }
    } while (!done);

    printf("closing dtrace\n");
    dtrace_close(g_dtp);

    return 0;
}

