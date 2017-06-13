LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libqltipc-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS)
LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../../include/libqltipc
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/../interface/include
LOCAL_SRC_FILES := \
	ipc.c \
	ipc_dev.c \
	libtipc.c \
	rpmb_proxy.c \
	avb.c \
	arch/x86/trusty_dev.c \
	arch/x86/trusty_mem.c \
	storage_ops_osloader.c \
	sysdeps_osloader.c

include $(BUILD_EFI_STATIC_LIBRARY)
