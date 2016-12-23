LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := wrapper.c
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
FIRST_BUILD_ID := $(shell echo $(BUILD_ID) | cut -c 1)
ifeq ($(FIRST_BUILD_ID),O)
LOCAL_CFLAGS := -I $(LOCAL_PATH)/../include/libkernelflinger
LOCAL_STATIC_LIBRARIES := libgnuefi libefi
#libkernelflinger-$(TARGET_BUILD_VARIANT) #cause dependency cycle error in Android O
else
LOCAL_STATIC_LIBRARIES := libgnuefi libefi libkernelflinger-$(TARGET_BUILD_VARIANT)
endif
LOCAL_MODULE := libsslsupport
include $(BUILD_EFI_STATIC_LIBRARY)

ifeq ($(KERNELFLINGER_SSL_LIBRARY),)
    KERNELFLINGER_SSL_LIBRARY := boringssl
endif

ifneq (,$(filter boringssl, $(KERNELFLINGER_SSL_LIBRARY)))
    KERNELFLINGER_SSL_LIBRARY_PATH := external/boringssl
endif

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
    KERNELFLINGER_SSL_LIBRARY_PATH := vendor/intel/external/openssl
endif

include $(CLEAR_VARS)
LOCAL_PATH := $(KERNELFLINGER_SSL_LIBRARY_PATH)

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/build-config-64.mk
include $(LOCAL_PATH)/build-config-32.mk
endif

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_ARCH := x86_64
LOCAL_2ND_ARCH := 64
else
LOCAL_ARCH := x86
LOCAL_2ND_ARCH := 32
endif

# The static library should be used in only unbundled apps
# and we don't have clang in unbundled build yet.
# in Android O, include in ../r11/platforms/android-$(LOCAL_SDK_VERSION)/
FIRST_BUILD_ID := $(shell echo $(BUILD_ID) | cut -c 1)
ifeq ($(FIRST_BUILD_ID),O)
LOCAL_SDK_VERSION := 24
NDK_DIR := r11
else
LOCAL_SDK_VERSION := 9
NDK_DIR := current
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libuefi_crypto_static
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/android-config.mk $(LOCAL_PATH)/Crypto.mk
ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/Crypto-config-target.mk
include $(LOCAL_PATH)/android-config.mk
# Replace cflags with static-specific cflags so we dont build in libdl deps
LOCAL_CFLAGS_32 := $(openssl_cflags_static_32)
LOCAL_CFLAGS_64 := $(openssl_cflags_static_64)
endif
ifneq (,$(filter boringssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/crypto-sources.mk
endif
LOCAL_SRC_FILES := $(LOCAL_SRC_FILES_$(LOCAL_ARCH))
LOCAL_CFLAGS += $(LOCAL_CFLAGS_$(LOCAL_ARCH)) $(LOCAL_CFLAGS_$(LOCAL_2ND_ARCH)) $(openssl_cflags_static_$(LOCAL_2ND_ARCH))
LOCAL_SRC_FILES_x86 :=
LOCAL_SRC_FILES_x86_64 :=
LOCAL_CFLAGS_32 :=
LOCAL_CFLAGS_64 :=
LOCAL_CFLAGS_x86 :=
LOCAL_CFLAGS_x86_64 :=

LOCAL_CFLAGS += -isystem $(HISTORICAL_NDK_VERSIONS_ROOT)/$(NDK_DIR)/platforms/android-$(LOCAL_SDK_VERSION)/arch-$(LOCAL_ARCH)/usr/include
include $(BUILD_EFI_STATIC_LIBRARY)

#######################################
# target static library
include $(CLEAR_VARS)
LOCAL_PATH := $(KERNELFLINGER_SSL_LIBRARY_PATH)

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/build-config-64.mk
include $(LOCAL_PATH)/build-config-32.mk
endif

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_ARCH := x86_64
LOCAL_2ND_ARCH := 64
else
LOCAL_ARCH := x86
LOCAL_2ND_ARCH := 32
endif

# The static library should be used in only unbundled apps
# and we don't have clang in unbundled build yet.
# in Android O, include in ../r11/platforms/android-$(LOCAL_SDK_VERSION)/
FIRST_BUILD_ID := $(shell echo $(BUILD_ID) | cut -c 1)
ifeq ($(FIRST_BUILD_ID),O)
LOCAL_SDK_VERSION := 24
NDK_DIR := r11
else
LOCAL_SDK_VERSION := 9
NDK_DIR := current
endif

ifneq (,$(filter openssl, $(KERNELFLINGER_SSL_LIBRARY)))
LOCAL_SRC_FILES += $(target_src_files)
LOCAL_CFLAGS += $(target_c_flags)
LOCAL_C_INCLUDES += $(target_c_includes)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/android-config.mk $(LOCAL_PATH)/Ssl.mk
include $(LOCAL_PATH)/Ssl-config-target.mk
include $(LOCAL_PATH)/android-config.mk
LOCAL_SRC_FILES := $(LOCAL_SRC_FILES_$(LOCAL_ARCH))
endif
ifneq (,$(filter boringssl, $(KERNELFLINGER_SSL_LIBRARY)))
include $(LOCAL_PATH)/sources.mk
LOCAL_SRC_FILES := $(crypto_sources) $(linux_$(LOCAL_ARCH)_sources)
ifeq ($(FIRST_BUILD_ID),O)
LOCAL_CFLAGS += -I$(LOCAL_PATH)/../../hardware/intel/kernelflinger/libsslsupport/borningssl
endif
endif
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libuefi_ssl_static
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CFLAGS += $(LOCAL_CFLAGS_$(LOCAL_ARCH)) $(LOCAL_CFLAGS_$(LOCAL_2ND_ARCH)) $(openssl_cflags_static_$(LOCAL_2ND_ARCH))
LOCAL_SRC_FILES_x86 :=
LOCAL_SRC_FILES_x86_64 :=
LOCAL_CFLAGS_32 :=
LOCAL_CFLAGS_64 :=
LOCAL_CFLAGS_x86 :=
LOCAL_CFLAGS_x86_64 :=

LOCAL_CFLAGS += -std=c99
LOCAL_CFLAGS += -I$(LOCAL_PATH)/include
LOCAL_CFLAGS += -DOPENSSL_NO_THREADS
LOCAL_CFLAGS += -isystem $(HISTORICAL_NDK_VERSIONS_ROOT)/$(NDK_DIR)/platforms/android-$(LOCAL_SDK_VERSION)/arch-$(LOCAL_ARCH)/usr/include
include $(BUILD_EFI_STATIC_LIBRARY)
