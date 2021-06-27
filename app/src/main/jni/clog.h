#ifndef __LOG_H_
#define __LOG_H_

#include <android/log.h>

#ifndef LOG_TAG
#define LOG_TAG "xx"
#define WITH_CRASH_LOG
//#define LOG_TAG "crash_collector"
#endif

#ifdef WITH_CRASH_LOG
#define CRASH_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define CRASH_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define CRASH_LOGE(...)
#define CRASH_LOGD(...)
#endif

#endif
