LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := libfastboot-$(TARGET_BUILD_VARIANT)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libfastboot
LOCAL_CFLAGS := -DKERNELFLINGER -Wall -Wextra -Werror \
	-DTARGET_BOOTLOADER_BOARD_NAME=\"$(TARGET_BOOTLOADER_BOARD_NAME)\"
LOCAL_STATIC_LIBRARIES := libefi libgnuefi libopenssl-efi libcryptlib \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

ifeq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_CFLAGS += -DUSER -DUSERDEBUG
endif

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    LOCAL_CFLAGS += -DUSERDEBUG
endif

LOCAL_SRC_FILES := \
	fastboot.c \
	fastboot_oem.c \
	fastboot_usb.c \
	fastboot_ui.c \
	flash.c \
	gpt.c \
	sparse.c \
	uefi_utils.c \
	smbios.c \
	info.c \
	intel_variables.c \
	oemvars.c \
	hashes.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include/libfastboot

include $(BUILD_EFI_STATIC_LIBRARY)

