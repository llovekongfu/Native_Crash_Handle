//
// Created by Apple on 2021/4/13.
//

#include <pthread.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctime>
#include <asm/sigcontext.h>
#include <asm/signal.h>
#include <cstdlib>
#include "NativeBacktrace.h"
#include "clog.h"
#include "Test.h"
#include <unwind.h>
#include <map>

#ifndef SIGNALS_NUM
#define SIGNALS_NUM(x)  ((int)(sizeof(x)/sizeof((x)[0])))
#endif

JavaVM* jvm;
JNIEnv *env;
static char* crashFilePath;
int sdkVersion;
jclass gCrashUtil;
jmethodID mJavaBackTrace;

pthread_t mThread;
int tid;
char* javaCrashChar;
bool isAttached;
pthread_cond_t sigCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t sigMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t endCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t endMutex = PTHREAD_MUTEX_INITIALIZER;
int mSignals[] = {SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGPIPE};
struct sigaction oldActs[SIGNALS_NUM(mSignals)];
Test test;

NativeBacktrace::NativeBacktrace(JavaVM *vm) {
    jvm = vm;
}
int NativeBacktrace::getData() {
    return test.getTestData();
}

void NativeBacktrace::handleSignal(int signo, siginfo_t* info, void* context) {
    CRASH_LOGD("handleSignal== ");
    int result = jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (result != JNI_OK) {
        return;
    }
    tid = gettid();
    int fd = open(crashFilePath, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == -1) {
        exit(0);
    }
    if (tid != 0 && mThread != NULL && mJavaBackTrace != NULL) {
        pthread_mutex_lock(&sigMutex);
        pthread_cond_signal(&sigCond);
        pthread_mutex_unlock(&sigMutex);
        WaitGetJavaCrashInfo();
    }
    CRASH_LOGD("***************record crash info************************");
    writeFile(fd, "***************record crash info************************\n");
    writeFile(fd, "record time: %s\n", NativeBacktrace::getLocalTime());
    writeFile(fd, "***************record java backtrace************************\n");
    write(fd, javaCrashChar, strlen(javaCrashChar));
//    initCorkScrew();
//    if (sdkVersion < 21) {
//        initCorkScrew();
//        char lines[MAX_BACKTRACE_SIZE] = {0};
//        if (unwind_backtrace_signal_arch != NULL && info != NULL) {
//            map_info_t *map_info = acquire_my_map_info_list();
//            backtrace_frame_t frames[256] = {0,};
//            backtrace_symbol_t symbols[256] = {0,};
//            const ssize_t size = unwind_backtrace_signal_arch(info, context, map_info, frames, 0,
//                                                              255);
//            get_backtrace_symbols(frames, size, symbols);
//
//            for (int i = 0; i < size; ++i) {
//                char line[MAX_BACKTRACE_SIZE];
//                const char *method = symbols[i].demangled_name;
//                if (!method) {
//                    method = symbols[i].symbol_name;
//                }
//                const char *file = symbols[i].map_name;
//                if (!file) {
//                    file = "<unknown>";
//                }
//
//                size_t fieldWidth = (MAX_BACKTRACE_SIZE - 80) / 2;
//                if (method) {
//                    uintptr_t pc_offset = symbols[i].relative_pc
//                                          - symbols[i].relative_symbol_addr;
//                    if (pc_offset) {
//                        snprintf(line, MAX_BACKTRACE_SIZE,
//                                 "#%02d  pc %08x  %.*s (%.*s+%u)", i,
//                                 symbols[i].relative_pc, fieldWidth, file,
//                                 fieldWidth, method, pc_offset);
//                    } else {
//                        snprintf(line, MAX_BACKTRACE_SIZE,
//                                 "#%02d  pc %08x  %.*s (%.*s)", i,
//                                 symbols[i].relative_pc, fieldWidth, file,
//                                 fieldWidth, method);
//                    }
//                } else {
//                    method = "<unknown>";
//                    snprintf(line, MAX_BACKTRACE_SIZE,
//                             "#%02d  pc %08x  %.*s", i, symbols[i].relative_pc,
//                             fieldWidth, file);
//                }
//                snprintf(lines, sizeof(lines), "%s \n%s", lines, line);
//
//            }
//            free_backtrace_symbols(symbols, size);
//            release_my_map_info_list(map_info);
//            writeFile(fd, lines);
//        }
//
//    } else if (sdkVersion >= 21) {
        handleNativeCrash(fd, signo, info, static_cast<ucontext_t *>(context));
//    }
    exit(0);
}

void NativeBacktrace::init(char *filePath, int len, int version) {
    if (crashFilePath != NULL) {
        delete[] crashFilePath;
    }
    crashFilePath = new char[len + 1];
    memset(crashFilePath, 0, (len + 1) * sizeof(char));
    //保存文件路径信息
    memcpy(crashFilePath, filePath, len * sizeof(char));
    crashFilePath[len] = 0;
    sdkVersion = version;
    int result = jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (result != JNI_OK) {
        isAttached = JNI_TRUE;
        return;
    }
    jclass crashUtil = env->FindClass("com/example/nativecrash/NativeCrashUtil");
    gCrashUtil = (jclass) env->NewGlobalRef(crashUtil);
    if (crashUtil != NULL) {
        //获取Java层函数方法ID
        mJavaBackTrace = env->GetStaticMethodID(crashUtil, "getJavaBackTrace","(I)Ljava/lang/String;");
    }
    //创建获取Java层崩溃栈信息线程
    initDumpThread();
    //初始化信号处理函数
    initHandleSignal();
    checkException(env);
    env->DeleteLocalRef(crashUtil);
}

int NativeBacktrace::checkException(JNIEnv *env) {
    if(env->ExceptionCheck()) {
        env->ExceptionDescribe(); // writes to logcat
        env->ExceptionClear();
        return 1;
    }
    return -1;
}

void* NativeBacktrace::handleDumpInfo(void *data) {
    int status;
    JNIEnv* curEnv;
    jboolean isAttached = JNI_FALSE;
    status = jvm->GetEnv((void **) &curEnv, JNI_VERSION_1_4);
    if (status < 0) {
        //将当前线程注册到虚拟机中．
        status = jvm->AttachCurrentThread(&curEnv, NULL);
        if (status < 0) return NULL;
        isAttached = JNI_TRUE;
    }
    pthread_mutex_lock(&sigMutex);
    while (tid == 0) {
        pthread_cond_wait(&sigCond, &sigMutex);
    }
    jstring javaCrashInfo = (jstring) curEnv->CallStaticObjectMethod(gCrashUtil, mJavaBackTrace,
                                                                     tid);
    if (javaCrashInfo == NULL) {
        return NULL;
    }
    int len = curEnv->GetStringLength(javaCrashInfo);
    javaCrashChar = new char[len + 1];
    memset(javaCrashChar, 0, len + 1);
    char* info = (char *) curEnv->GetStringUTFChars(javaCrashInfo, NULL);
    memcpy(javaCrashChar, info, len);
    curEnv->ReleaseStringUTFChars(javaCrashInfo, info);
    pthread_mutex_unlock(&sigMutex);
    pthread_mutex_lock(&endMutex);
    pthread_cond_signal(&endCond);
    pthread_mutex_unlock(&endMutex);
    if (isAttached) {
        //将线程从jvm中注销
        jvm->DetachCurrentThread();
    }
    return NULL;
}

void NativeBacktrace::initDumpThread(){
    if (mJavaBackTrace != NULL) {
        pthread_create(&mThread, NULL, handleDumpInfo, NULL);
    }
}

void NativeBacktrace::initCorkScrew(){
    void * libcorkscrew = dlopen("libcorkscrew.so", RTLD_LAZY | RTLD_LOCAL);
    if (libcorkscrew) {
        unwind_backtrace_signal_arch = (t_unwind_backtrace_signal_arch) dlsym(
                libcorkscrew, "unwind_backtrace_signal_arch");
        acquire_my_map_info_list = (t_acquire_my_map_info_list) dlsym(
                libcorkscrew, "acquire_my_map_info_list");
        release_my_map_info_list = (t_release_my_map_info_list) dlsym(
                libcorkscrew, "release_my_map_info_list");
        get_backtrace_symbols = (t_get_backtrace_symbols) dlsym(libcorkscrew,
                                                                "get_backtrace_symbols");
        free_backtrace_symbols = (t_free_backtrace_symbols) dlsym(libcorkscrew,
                                                                  "free_backtrace_symbols");
    }
}

void NativeBacktrace::initHandleSignal() {
    CRASH_LOGD("initHandleSignal== ");
    //尝试设置，此时使用sa_handler作为信号处理函数
    for (int i = 0; i < SIGNALS_NUM(mSignals); ++i) {
        if (sigaction(mSignals[i], NULL, &oldActs[i]) == -1) {
            //如果有信号尝试设置失败，则直接返回
            return;
        }
    }
    //处理栈溢出
    stack_t stack;
    memset(&stack, 0, sizeof(stack));
    stack.ss_size = 1024 * 128;
    stack.ss_sp = malloc(stack.ss_size);
    stack.ss_flags = 0;
    sigaltstack(&stack, NULL);

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    //初始化信号集
    sigemptyset(&action.sa_mask);
    for (int i = 0; i < SIGNALS_NUM(mSignals); ++i) {
        //添加信号到信号集中
        sigaddset(&action.sa_mask, mSignals[i]);
    }
    //指定信号处理函数
    action.sa_sigaction = handleSignal;
    //指定信号处理行为
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;

    for (int i = 0; i < SIGNALS_NUM(mSignals); ++i) {
        //注册信号集、信号处理函数和信号处理行为等
        sigaction(mSignals[i], &action, NULL);
        CRASH_LOGD("mSignals== %d", mSignals[i]);
    }
}

void NativeBacktrace::handleNativeCrash(int fd, int signo, siginfo_t* sigInfo, ucontext_t* context) {
    if (fd == -1) {
        return;
    }
    writeFile(fd,"***************record native crash backtrace************************\n");
    writeFile(fd,"\ncrash time: %s", getLocalTime());
    writeFile(fd,"\npid: %s  uid: %s  process: %s", sigInfo->_sifields._kill._pid, sigInfo->_sifields._kill._uid, getProcessName(sigInfo->_sifields._kill._pid));
    writeFile(fd,"\nsignal number: %d(%s)  signal code: %d(%s)  signal error: %d  fault addr %08x", signo, getSignalName(signo), sigInfo->si_code,getCodeName(sigInfo->si_code) ,sigInfo->si_errno, sigInfo->si_addr);
    writeFile(fd,"\nRegister Data: \n");
    writeRegisterData(fd, (const ucontext_t *) context);
    dumpBacktrace(fd);
}

void NativeBacktrace::WaitGetJavaCrashInfo() {
    struct timeval nowTime;
    gettimeofday(&nowTime,NULL);
    struct timespec outTime;
    outTime.tv_sec = nowTime.tv_sec + WAIT_GET_JAVA_CRASH_TIME;
    outTime.tv_nsec=0;
    pthread_mutex_lock(&endMutex);
    pthread_cond_timedwait(&endCond, &endMutex, &outTime);
    pthread_mutex_unlock(&endMutex);
}

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg) {
    backtrace_state_t* state = static_cast<backtrace_state_t*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
#if __thumb__
        const uintptr_t thumb_bit = 1;
        pc &= ~thumb_bit;
#endif
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            //保存每次回调的pc值
            *state->current++ = reinterpret_cast<void *>(pc);
        }
    }
    return _URC_NO_REASON;
}

void NativeBacktrace::dumpBacktrace(int fd) {
    writeFile(fd, "\nBacktrace:\n");
    const size_t count = 30;
    void* buffer[count];
    backtrace_state_t state = {buffer, buffer + count};
    _Unwind_Backtrace(unwind_callback, &state);

    size_t max = state.current - buffer;

    for (size_t idx = 0; idx < max; ++idx) {
        const void* addr = buffer[idx];
        const char* func_name = "";
        const char* file_name = "";

        Dl_info info;
        if (dladdr(addr, &info) && info.dli_fname != NULL) {
            func_name = info.dli_sname;
            file_name = info.dli_fname;
            unsigned long offset = (char *) addr - (char *) info.dli_fbase;
            char* demangled_func = NULL;
            char* demangled_file = NULL;

#if ENABLE_DEMANGLING
            int status = 0;
            demangled_func = __cxa_demangle(func_name, NULL, NULL, &status);
            demangled_file = __cxa_demangle(file_name, NULL, NULL, &status);
            if (demangled_func)
                func_name = demangled_func;
            if (demangled_file)
                file_name = demangled_file;
#endif

            CRASH_LOGD(" $%02d %08x %s (%s)\n", idx, offset, file_name, func_name);
            writeFile(fd, "  at: %02d %08x %s (%s)\n", idx, offset, file_name, func_name);
            free(demangled_func);
            free(demangled_file);
        }
    }
}

void NativeBacktrace::writeFile(int fd, const char *content, ...) {
    va_list argp;
    va_start(argp, content);
    char buffer[256];
    memset(buffer, 0, strlen(buffer));
    vsprintf(buffer, content, argp);
    va_end(argp);
    write(fd, buffer, strlen(buffer));
}

char* NativeBacktrace::getLocalTime() {
    char timeStr[40];
    long milliSeconds;
    char localTimeStr[128];
    timeval currentTimeTmp;
    gettimeofday(&currentTimeTmp, NULL);
    tm* ptm = localtime (&(currentTimeTmp.tv_sec));
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", ptm);
    milliSeconds = currentTimeTmp.tv_usec/1000;
    snprintf (localTimeStr, strlen(localTimeStr), "%s.%03ld", timeStr, milliSeconds);
    return timeStr;
}

void NativeBacktrace::writeRegisterData(int fd, const ucontext_t *ucontext) {
    std::string ctxTxt;
#if defined(__aarch64__)
    for (int i = 0; i < 30; ++i) {
        if (i % 4 == 0) {
            writeFile(fd, "     ");
        }
        writeFile(fd, "x%d %016lx ", i, ucontext->uc_mcontext.regs[i]);
        if ((i + 1) % 4 == 0) {
            writeFile(fd, "\r\n");
        }
    }
    writeFile(fd, "\r\n");
    writeFile(fd, "     ");
    writeFile(fd, "sp %016lx ", ucontext->uc_mcontext.sp);
    writeFile(fd, "lr %016lx ", ucontext->uc_mcontext.regs[30]);
    writeFile(fd, "pc %016lx ", ucontext->uc_mcontext.pc);
#elif defined(__arm__)
    writeFile(fd,  " r0 %08lx ", ucontext->uc_mcontext.arm_r0);
    writeFile(fd,   "r1 %08lx ", ucontext->uc_mcontext.arm_r1);
    writeFile(fd,   "r2 %08lx ", ucontext->uc_mcontext.arm_r2);
    writeFile(fd,   "r3 %08lx ", ucontext->uc_mcontext.arm_r3);
    writeFile(fd,   "r4 %08lx ", ucontext->uc_mcontext.arm_r4);
    writeFile(fd,  "r5 %08lx ", ucontext->uc_mcontext.arm_r5);
    writeFile(fd,   "r6 %08lx ", ucontext->uc_mcontext.arm_r6);
    writeFile(fd,   "r7 %08lx ", ucontext->uc_mcontext.arm_r7);
    writeFile(fd,   "r8 %08lx\n ", ucontext->uc_mcontext.arm_r8);
    writeFile(fd,   "r9 %08lx ", ucontext->uc_mcontext.arm_r9);
    writeFile(fd,   "r10 %08lx ", ucontext->uc_mcontext.arm_r10);

    writeFile(fd,   "ip %08lx ", ucontext->uc_mcontext.arm_ip);
    writeFile(fd,   "sp %08lx ", ucontext->uc_mcontext.arm_sp);
    writeFile(fd,  "lr %08lx ", ucontext->uc_mcontext.arm_lr);
    writeFile(fd,   "pc %08lx ", ucontext->uc_mcontext.arm_pc);

#endif
}

char* NativeBacktrace::getProcessName(const int pid) {
    char processName[256] = {0};
    char cmd[64] = {0};
    sprintf(cmd, "/proc/%d/cmdline", pid);
    FILE *f = fopen(cmd, "r");
    if (f) {
        size_t size;
        size = fread(processName, sizeof(char), 256, f);
        if (size > 0 && '\n' == processName[size - 1]) {
            processName[size - 1] = '\0';
        }
        fclose(f);
    }
    return processName;
}

char *NativeBacktrace::getSignalName(const int signo) {
    char *result = NULL;
    switch (signo) {
        case SIGTRAP:
            result = "SIGTRAP";
            break;
        case SIGABRT:
            result = "SIGABRT";
            break;
        case SIGILL:
            result = "SIGILL";
            break;
        case SIGSEGV:
            result = "SIGSEGV";
            break;
        case SIGFPE:
            result = "SIGFPE";
            break;
        case SIGBUS:
            result = "SIGBUS";
            break;
        case SIGPIPE:
            result = "SIGPIPE";
            break;
        case SIGSYS:
            result = "SIGSYS";
            break;
        default:
            break;
    }
    return result;
}

char *NativeBacktrace::getCodeName(const int code) {
    char *result = NULL;
    switch (code) {
        case SI_USER:
            result = "SI_USER";
            break;
        case SI_KERNEL:
            result = "SI_KERNEL";
            break;
        case SI_QUEUE:
            result = "SI_QUEUE";
            break;
        case SI_TIMER:
            result = "SI_TIMER";
            break;
        case SI_MESGQ:
            result = "SI_MESGQ";
            break;
        case SI_ASYNCIO:
            result = "SI_ASYNCIO";
            break;
        case SI_SIGIO:
            result = "SI_SIGIO";
            break;
        case SI_TKILL:
            result = "SI_TKILL";
            break;
        case SI_DETHREAD:
            result = "SI_DETHREAD";
            break;
        default:
            break;
    }
    return result;
}




