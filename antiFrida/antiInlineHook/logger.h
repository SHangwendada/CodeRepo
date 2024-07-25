//
// Created by luoyesiqiu
//

#ifndef LOCAL_DLFCN_LOGGER_H
#define LOCAL_DLFCN_LOGGER_H

#include <android/log.h>

#define TAG "local_dlfcn"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#endif //LOCAL_DLFCN_LOGGER_H
