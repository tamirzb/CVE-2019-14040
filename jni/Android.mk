LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := qseecom_uaf
APP_ALLOW_MISSING_DEPS := true
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
LOCAL_LDFLAGS += -Wl,--unresolved-symbols=ignore-all
LOCAL_SRC_FILES := qseecom_uaf.c
include $(BUILD_EXECUTABLE)
