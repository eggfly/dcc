LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := nc
LOCAL_LDLIBS    := -llog

ifeq ($(TARGET_ARCH_ABI), armeabi-v7a)
	LOCAL_LDFLAGS += -Wl,--long-plt
endif

SOURCES := $(wildcard $(LOCAL_PATH)/nc/*.cpp)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/nc

LOCAL_SRC_FILES := $(SOURCES:$(LOCAL_PATH)/%=%)

include $(BUILD_SHARED_LIBRARY)
