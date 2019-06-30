#include <iostream>
#include <fstream>
#include <string>
#include <atomic>
#include <chrono>
#include <thread>

#include <unistd.h>

#include <dtrace.h>
#include <fcntl.h>

using namespace std;

static dtrace_hdl_t *g_dtp;

//atomic_int chewrec_count(0);
int chewrec_count = 0;
int chew_count = 0;
atomic_int processed_count(0);

static int chew(const dtrace_probedata_t *data, void *arg) {
    chew_count++;
    return (DTRACE_CONSUME_THIS);
}

static int chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg) {
    chewrec_count++;
    // A NULL rec indicates that we've processed the last record.
    if (rec == nullptr) {
        return (DTRACE_CONSUME_NEXT);
    }
    dtrace_actkind_t act = rec->dtrd_action;
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
    cerr << "errhandler: " << data->dteda_msg << endl;
    //error(data->dteda_msg);
    return (DTRACE_HANDLE_OK);
}

//static const char *g_prog = R"(BEGIN { printf("hello from dtrace\n"); ustack(10); }  profile-333{printf("tid: %lu, pid: %d",  tid, pid); ustack(100);})";
//static const char *g_prog = R"(BEGIN { printf("hello from dtrace\n"); ustack(10); }  profile-333/pid == $target/{printf("tid: %lu, pid: %d\n",  tid, pid);})";
//static const char *g_prog = R"(BEGIN { printf("hello from dtrace\n"); stack(); ustack(); }  END {ustack(10);})";
//static const char* g_prog = "syscall::open*:entry { printf(\"%s %s\\n\", execname, copyinstr(arg0)); }";

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

int init_dtrace(int target_pid) {
    int err;

    if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == nullptr) {
        fprintf(stderr, "failed to initialize dtrace: %s\n", dtrace_errmsg(nullptr, err));
        return -1;
    }
    cerr << "Dtrace initialized" << endl;

    dtrace_setopt(g_dtp, "bufsize", "4m");
    dtrace_setopt(g_dtp, "aggsize", "4m");
    cerr << "dtrace options set" << endl;

    /*target_process = dtrace_proc_grab(g_dtp, target_pid, 0);
    if (target_process == nullptr) {
        cerr << "dtrace grab process error" << endl;
        return -1;
    }
    cerr << "dtrace grab process with pid = " << target_pid << endl;*/

    if (dtrace_handle_err(g_dtp, &errhandler, nullptr) == -1)
        dfatal("failed to establish error handler");

    //static const char *g_prog = R"(BEGIN { printf("hello from dtrace\n"); ustack(10); }  profile-333/pid == /{printf("tid: %lu, pid: %d\n",  tid, pid);})";

    static const char* prefix = R"(BEGIN { printf("hello from dtrace\n"); ustack(10); }  profile-333)";
    static const char* suffix = R"({printf("tid: %lu, pid: %d\n",  tid, pid);})";
    string g_prog = string(prefix) + string("/pid == " + to_string(target_pid) + "/") + string(suffix);
    //static const string prog = string(R"(BEGIN { printf("hello from dtrace\n"); ustack(10); }  profile-333/pid == ");

    dtrace_prog_t *prog;
    if ((prog = dtrace_program_strcompile(g_dtp, g_prog.c_str(), DTRACE_PROBESPEC_NAME, 0, 0, nullptr)) == nullptr) {
        cerr << "failed to compile dtrace program" << endl;
        return -1;
    }
    cerr << "dtrace program compiled" << endl;

    dtrace_proginfo_t info = {};
    if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
        cerr << "failed to enable dtrace probes" << endl;
        return -1;
    }
    cerr << "dtrace probes enabled" << endl;
    return 0;
}

//read from fds[0], write into returned FILE*
FILE *init_pipe(int fds[]) {
    if (pipe(fds) != 0) {
        cerr << "can't create pipe" << endl;
        return nullptr;
    }
    int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags == -1) {
        cerr << "fcntl error" << endl;
        return nullptr;
    }
    fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

    return fdopen(fds[1], "a");
}

int main(int argc, char **argv) {
    int target_pid = stoi(argv[1]);

    if (init_dtrace(target_pid) < 0) {
        exit(-1);
    }

    if (dtrace_go(g_dtp) != 0) {
        cerr << "could not start instrumentation" << endl;
        return -1;
    }
    cerr << "instrumentation started .." << endl;

    int fds[2];
    FILE *faux_stdout = init_pipe(fds);

    auto progress_reporter = thread([]() {
        int seconds = 0;
        int previous_chewrec_count = 0;
        int previous_chew_count = 0;
        while (true) {
            this_thread::sleep_for(chrono::seconds(1));
            seconds++;
            int cur_rec = chewrec_count;
            int last_sec_rec = cur_rec - previous_chewrec_count;
            previous_chewrec_count = cur_rec;
            int cur = chew_count;
            int last_sec = cur - previous_chew_count;
            previous_chew_count = cur;
            cerr << seconds << " : chewrec for last second: " << last_sec_rec << ", chew for last second: "
                 << last_sec << endl;
        }
    });

    auto data_reader = thread([fds]() { //TODO: capture fd?
        ofstream log("data.log");
        char buf[1024 * 1024];
        while (true) {
            ssize_t num_read = read(fds[0], buf, sizeof(buf));
            log << buf;
            cerr << "read " << num_read << " bytes from pipe" << endl;
            if (num_read <= 0) {
                cerr << "nothing to read, sleep for 0.5sec" << endl;
                this_thread::sleep_for(chrono::milliseconds(500));
            }
        }
    });

    bool done = false;
    do {
        if (done) {
            if (dtrace_stop(g_dtp) == -1) {
                cerr << "could not stop tracing" << endl;
                return -1;
            }
        } else {
            dtrace_sleep(g_dtp); //XXX
        }

        switch (dtrace_work(g_dtp, /*faux_stdout*/stdout, chew, chewrec, nullptr)) {
            case DTRACE_WORKSTATUS_DONE:
                cerr << "DTRACE_WORKSTATUS_DONE" << endl;
                done = true;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                /*char buf[1024 * 1024];
                cerr << "read data from pipe" << endl;
                for (;;) {
                    ssize_t num_read = read(fds[0], buf, sizeof(buf));
                    cerr << "read " << num_read << " bytes from pipe" << endl;
                    if (num_read <= 0)
                        break;
                }*/
                break;
            default:
                fprintf(stderr, "processing aborted");
                return -1;
        }
    } while (!done);

    progress_reporter.detach();
    data_reader.detach();
    printf("closing dtrace\n");
    dtrace_close(g_dtp);

    return 0;
}


