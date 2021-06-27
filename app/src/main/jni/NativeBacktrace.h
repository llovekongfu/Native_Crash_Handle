//
// Created by Apple on 2021/4/13.
//

#ifndef NATIVECRASH_NATIVEBACKTRACE_H
#define NATIVECRASH_NATIVEBACKTRACE_H


#include <jni.h>
#include <sys/ucontext.h>
#if __arm__
#include "libunwind.h"
#endif

#include <unwind.h>

#define ENABLE_DEMANGLING 1
#if __cplusplus
extern "C"
#endif
char* __cxa_demangle(
        const char* mangled_name,
        char* output_buffer,
        size_t* length,
        int* status);

#include <assert.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <map>

#define MAX_BACKTRACE_SIZE (5 * 1024 * 1024)
#define WAIT_GET_JAVA_CRASH_TIME 5

typedef struct map_info_t map_info_t;
typedef struct {
    uintptr_t absolute_pc;
    uintptr_t stack_top;
    size_t stack_size;
} backtrace_frame_t;

struct backtrace_state_t {
    void** current;
    void** end;
};

static const size_t address_count_max = 30;

struct BacktraceState {
    const ucontext_t*   signal_ucontext;
    size_t              address_skip_count;
    size_t              pc_count;
    uintptr_t           pcs[address_count_max];

};
typedef struct BacktraceState BacktraceState;

typedef struct {
    uintptr_t relative_pc;
    uintptr_t relative_symbol_addr;
    char* map_name;
    char* symbol_name;
    char* demangled_name;
} backtrace_symbol_t;

typedef struct map_info_t map_info_t;
typedef ssize_t (*t_unwind_backtrace_signal_arch)(siginfo_t* si, void* sc, const map_info_t* lst, backtrace_frame_t* bt, size_t ignore_depth, size_t max_depth);
static t_unwind_backtrace_signal_arch unwind_backtrace_signal_arch;
typedef map_info_t* (*t_acquire_my_map_info_list)();
static t_acquire_my_map_info_list acquire_my_map_info_list;
typedef void (*t_release_my_map_info_list)(map_info_t* milist);
static t_release_my_map_info_list release_my_map_info_list;
typedef void (*t_get_backtrace_symbols)(const backtrace_frame_t* backtrace, size_t frames, backtrace_symbol_t* symbols);
static t_get_backtrace_symbols get_backtrace_symbols;
typedef void (*t_free_backtrace_symbols)(backtrace_symbol_t* symbols, size_t frames);
static t_free_backtrace_symbols free_backtrace_symbols;

typedef ssize_t (*t_unwind_backtrace_signal_arch)(siginfo_t* si, void* sc, const map_info_t* lst, backtrace_frame_t* bt, size_t ignore_depth, size_t max_depth);

class NativeBacktrace {
public:
    NativeBacktrace(JavaVM *vm);
    int getData();
    void init(char *filePath, int len, int version);
    int checkException(JNIEnv *env);
    static void* handleDumpInfo(void* data);
    void initDumpThread();
    static void handleSignal(int signo, siginfo_t* info, void* context);
    void initHandleSignal();
    static void initCorkScrew();
    static void handleNativeCrash(int fd, int signo, siginfo_t* sigInfo, ucontext_t* context);
    static void writeFile(int fd, const char* content, ...);
    static char* getLocalTime();
    static void WaitGetJavaCrashInfo();
    static void dumpBacktrace(int fd);
    static void writeRegisterData(int fd, const ucontext_t *ucontext);
    static char* getProcessName(const int pid);
    static char* getSignalName(const int signo);
    static char* getCodeName(const int si_code);

private:
};


#endif //NATIVECRASH_NATIVEBACKTRACE_H
