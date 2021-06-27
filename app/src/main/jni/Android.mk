LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := eng

CRASH_SRC    :=     $(LOCAL_PATH)

LOCAL_SRC_FILES += \
        $(foreach DIR, $(CRASH_SRC), $(wildcard $(addsuffix /*.cpp, $(DIR))))

LOCAL_C_INCLUDES += $(JNI_H_INCLUDE)

LOCAL_C_INCLUDES += \
	$(JNI_H_INCLUDE) \
	$(CRASH_SRC)

LOCAL_CFLAGS += -Wall -Wextra -Wno-non-virtual-dtor -DNDEBUG -DOS_LINUX

ifeq ($(WITH_SYMBOL_TABLE),true)
  LOCAL_CFLAGS += -O0 -ggdb3 -fno-inline -g
else
  LOCAL_CFLAGS += -O2
endif

ifeq ($(WITH_CRASH_LOG),true)
  LOCAL_CFLAGS += -DWITH_CRASH_LOG=1
endif

LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog

#LOCAL_SHARED_LIBRARIES := libdl

LOCAL_PRELINK_MODULE := false

LOCAL_MODULE:= native_crash

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_STATIC_LIBRARY)
