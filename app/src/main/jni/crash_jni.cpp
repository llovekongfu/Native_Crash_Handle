#include <jni.h>
#include <string>
#include <assert.h>
#include "NativeBacktrace.h"
#include "clog.h"

#ifndef METHODS_NUM
#define METHODS_NUM(x)  ((int)(sizeof(x)/sizeof((x)[0])))
#endif

NativeBacktrace *backtrace;
using namespace std;
static void SignalHandler(int signo, siginfo_t* info, void* context);

static jint stringFromJNI(JNIEnv *env, jobject clazz, jint index) {
    int* value = NULL;
    CRASH_LOGD("index== %d", index == 2);
    if(index >= 2){
        return backtrace->getData();
    }
    return 22;
}

static void jni_init(JNIEnv *env, jobject clazz, jbyteArray filePath, jint len, jint version) {
    jbyte* path = env->GetByteArrayElements(filePath, NULL);

    if (backtrace == NULL || path == NULL || len < 1) {
        return;
    }
    backtrace->init(reinterpret_cast<char *>(path), len, version);
    env->ReleaseByteArrayElements(filePath, path, NULL);
}

static JNINativeMethod gMethods[] = {
        {"getStringFromJNI", "(I)I", (void *) stringFromJNI},
        {"init", "([BII)V", (void *) jni_init},
};

static int registerNatives(JNIEnv *env) {
    const char* className = "com/example/nativecrash/NativeCrashUtil";
    //获取声明native方法的类
    jclass cCrashUtil = env->FindClass(className);
    if (cCrashUtil == NULL) {
        return JNI_FALSE;
    }
    /*
     * 注册函数
     * 参数1：java类
     * 参数2：需要注册的函数数组
     * 参数3：注册函数的个数
     */
    if (env->RegisterNatives(cCrashUtil, gMethods, METHODS_NUM(gMethods)) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv* env = NULL;
    //获取JNIEnv
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
    assert(env != NULL);
    //注册函数
    if (!registerNatives(env)) {
        return -1;
    }
    backtrace = new NativeBacktrace(vm);
    //返回jni的版本
    return JNI_VERSION_1_6;
}