LOCAL_PATH := $(call my-dir)

SHARED_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libfastboot
SHARED_CFLAGS := -DKERNELFLINGER -Wall -Wextra -Werror \
	-DTARGET_BOOTLOADER_BOARD_NAME=\"$(TARGET_BOOTLOADER_BOARD_NAME)\"
SHARED_STATIC_LIBRARIES := libefi libgnuefi libopenssl-efi libcryptlib \
	libkernelflinger-$(TARGET_BUILD_VARIANT)
SHARED_C_INCLUDES := $(LOCAL_PATH)/../include/libfastboot

ifeq ($(TARGET_BUILD_VARIANT),user)
    SHARED_CFLAGS += -DUSER -DUSERDEBUG
endif

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    SHARED_CFLAGS += -DUSERDEBUG
endif

SHARED_SRC_FILES := \
	fastboot.c \
	fastboot_oem.c \
	flash.c \
	gpt.c \
	sparse.c \
	uefi_utils.c \
	smbios.c \
	info.c \
	intel_variables.c \
	oemvars.c \
	bootmgr.c \
	hashes.c \
	text_parser.c

include $(CLEAR_VARS)

LOCAL_MODULE := libfastboot-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_STATIC_LIBRARIES := $(SHARED_STATIC_LIBRARIES)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(SHARED_EXPORT_C_INCLUDE_DIRS)
LOCAL_C_INCLUDES := $(SHARED_C_INCLUDES)
LOCAL_SRC_FILES := $(SHARED_SRC_FILES) \
	fastboot_usb.c \
	fastboot_ui.c \

include $(BUILD_EFI_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libfastboot-for-installer-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_STATIC_LIBRARIES := $(SHARED_STATIC_LIBRARIES)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(SHARED_EXPORT_C_INCLUDE_DIRS)
LOCAL_C_INCLUDES := $(SHARED_C_INCLUDES)
LOCAL_SRC_FILES := $(SHARED_SRC_FILES)

include $(BUILD_EFI_STATIC_LIBRARY)

