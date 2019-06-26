LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libqltipc-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_CFLAGS += -DARCH_X86_64=1
else
LOCAL_CFLAGS += -DARCH_X86_32=1
endif

LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../../include/libqltipc
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/../interface/include \
                    $(LOCAL_PATH)/../../include

ifeq ($(BOARD_AVB_ENABLE),true)
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../avb
endif

LOCAL_SRC_FILES := \
	ipc.c \
	ipc_dev.c \
	libtipc.c \
	rpmb_proxy.c \
	avb.c \
	arch/x86/trusty_dev.c \
	arch/x86/trusty_mem.c \
	storage_ops_osloader.c \
	sysdeps_osloader.c \
	util.c \
	keymaster.c \
	keymaster_serializable.c \
	rpmb_sim.c \

ifeq ($(KERNELFLINGER_TRUSTY_PLATFORM),$(filter $(KERNELFLINGER_TRUSTY_PLATFORM), vsbl ovmf))
LOCAL_CFLAGS += -DHYPERVISOR_ACRN
endif

include $(BUILD_EFI_STATIC_LIBRARY)
