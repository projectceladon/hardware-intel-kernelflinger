LOCAL_PATH:= $(call my-dir)

################################
include $(CLEAR_VARS)

LOCAL_SRC_FILES := png2c.c
LOCAL_STATIC_LIBRARIES := libpng libz
LOCAL_C_INCLUDES += external/libpng
LOCAL_CFLAGS += -O2 -g -Wall -Werror -pedantic
LOCAL_MODULE := png2c

include $(BUILD_HOST_EXECUTABLE)
