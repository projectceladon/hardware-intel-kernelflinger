LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_UEFI_ARCH),i386)
arch_name := x86
else
arch_name := x86_64
endif

include $(CLEAR_VARS)
LOCAL_MODULE := gummiboot.efi
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/efi
LOCAL_MODULE_STEM := gummiboot.efi
LOCAL_SRC_FILES := ../../prebuilts/tools/linux-$(arch_name)/gummiboot/gummiboot.efi
LOCAL_CERTIFICATE := SBSIGN
LOCAL_SBSIGN_CERTIFICATE := uefi_bios_db_key
include $(BUILD_PREBUILT)

GUMMIBOOT_EFI := $(PRODUCT_OUT)/efi/gummiboot.efi

