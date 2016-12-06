KERNELFLINGER_LOCAL_PATH := $(call my-dir)
KERNELFLINGER_CFLAGS := -Wall -Wextra -Werror -mrdrnd

ifeq ($(TARGET_USE_TRUSTY),true)
    KERNELFLINGER_CFLAGS += -DUSE_TRUSTY
endif

ifeq ($(TARGET_USE_MULTIBOOT),true)
    KERNELFLINGER_CFLAGS += -DUSE_MULTIBOOT
endif

ifeq ($(TARGET_BUILD_VARIANT),user)
    KERNELFLINGER_CFLAGS += -DUSER -DUSERDEBUG
endif

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    KERNELFLINGER_CFLAGS += -DUSERDEBUG
endif

ifeq ($(TARGET_NO_DEVICE_UNLOCK),true)
    KERNELFLINGER_CFLAGS += -DNO_DEVICE_UNLOCK
endif

ifeq ($(BUILD_ANDROID_THINGS),true)
    KERNELFLINGER_CFLAGS += -DBUILD_ANDROID_THINGS
endif

ifeq ($(HAL_AUTODETECT),true)
    KERNELFLINGER_CFLAGS += -DHAL_AUTODETECT
endif

ifeq ($(TARGET_USE_USERFASTBOOT),true)
    $(error Userfastboot is not supported anymore)
endif

ifeq ($(KERNELFLINGER_USE_POWER_BUTTON),true)
    KERNELFLINGER_CFLAGS += -DUSE_POWER_BUTTON
endif

# adb in crashmode allows to pull the entire RAM and MUST never be
# disabled allowed on a USER build for security reasons:
ifneq ($(TARGET_BUILD_VARIANT),user)
    KERNELFLINGER_CFLAGS += -DCRASHMODE_USE_ADB
endif

ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    KERNELFLINGER_CFLAGS += -DUSE_UI
endif

ifneq ($(strip $(TARGET_BOOTLOADER_POLICY)),)
    KERNELFLINGER_CFLAGS += -DBOOTLOADER_POLICY=$(TARGET_BOOTLOADER_POLICY)
    # Double negation to enforce the use of the EFI variable storage
    # as the default behavior.
    ifneq ($(strip $(TARGET_BOOTLOADER_POLICY_USE_EFI_VAR)),False)
        KERNELFLINGER_CFLAGS += -DBOOTLOADER_POLICY_EFI_VAR
    endif
endif

ifeq ($(KERNELFLINGER_OS_SECURE_BOOT),true)
    KERNELFLINGER_CFLAGS += -DOS_SECURE_BOOT
endif

KERNELFLINGER_STATIC_LIBRARIES := \
	libuefi_ssl_static \
	libuefi_crypto_static \
	libgnuefi \
	libsslsupport \
	libefi

LOCAL_CLANG_EXCEPTION_PROJECTS += $(KERNELFLINGER_LOCAL_PATH)

include $(call all-subdir-makefiles)
LOCAL_PATH := $(KERNELFLINGER_LOCAL_PATH)

SHARED_CFLAGS := $(KERNELFLINGER_CFLAGS)
SHARED_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

include $(CLEAR_VARS)

# if dm-verity is disabled for eng purpose skip the oem-cert
ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY), true)
kf_intermediates := $(call intermediates-dir-for,EFI,kernelflinger)

VERITY_CERT := $(kf_intermediates)/verity.cer
PADDED_VERITY_CERT := $(kf_intermediates)/verity.padded.cer
OEMCERT_OBJ := $(kf_intermediates)/oemcert.o

$(VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
	$(transform-pem-cert-to-der-cert)

$(PADDED_VERITY_CERT): $(VERITY_CERT)
	$(call pad-binary, 4096)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

sym_binary := $(shell echo _binary_$(PADDED_VERITY_CERT) | sed "s/[\/\.-]/_/g")
$(OEMCERT_OBJ): $(PADDED_VERITY_CERT)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(sym_binary)_start=_binary_oemcert_start \
                       --redefine-sym $(sym_binary)_end=_binary_oemcert_end \
                       --redefine-sym $(sym_binary)_size=_binary_oemcert_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES := $(OEMCERT_OBJ)
else
ifneq (,$(filter user userdebug, $(TARGET_BUILD_VARIANT)))

fail_no_oem_cert:
	$(error Trying to build kernelflinger-$(TARGET_BUILD_VARIANT)\
without oem-cert, this is allowed only for eng builds)

LOCAL_GENERATED_SOURCES := fail_no_oem_cert
endif
endif # PRODUCT_SUPPORTS_VERITY

LOCAL_SRC_FILES := \
	kernelflinger.c
ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
	LOCAL_SRC_FILES += \
	ux.c
endif

LOCAL_STATIC_LIBRARIES += \
	libfastboot-$(TARGET_BUILD_VARIANT) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT)
ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_STATIC_LIBRARIES += libadb-$(TARGET_BUILD_VARIANT)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_SRC_FILES += unittest.c
endif

LOCAL_MODULE := kernelflinger-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY), true)
LOCAL_OBJCOPY_FLAGS := -j .oemkeys
endif
LOCAL_STATIC_LIBRARIES += $(SHARED_STATIC_LIBRARIES)
LOCAL_MODULE_STEM := kernelflinger

include $(BUILD_EFI_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := installer-$(TARGET_BUILD_VARIANT)
LOCAL_STATIC_LIBRARIES := \
	$(SHARED_STATIC_LIBRARIES) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libfastboot-for-installer-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_SRC_FILES := installer.c
LOCAL_MODULE_STEM := installer
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,libfastboot)
include $(BUILD_EFI_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := kf4abl-$(TARGET_BUILD_VARIANT)
LOCAL_MODULE_STEM := kf4abl
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_STATIC_LIBRARIES += \
	libfastboot-$(TARGET_BUILD_VARIANT) \
	libefiusb-$(TARGET_BUILD_VARIANT) \
	libefitcp-$(TARGET_BUILD_VARIANT) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	$(SHARED_STATIC_LIBRARIES) \
	libpayload \
	libefiwrapper-$(TARGET_BUILD_VARIANT) \
	libefiwrapper_drivers-$(TARGET_BUILD_VARIANT) \
	efiwrapper-$(TARGET_BUILD_VARIANT)
ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_STATIC_LIBRARIES += libadb-$(TARGET_BUILD_VARIANT)
endif
LOCAL_SRC_FILES := \
	kf4abl.c
include $(BUILD_ABL_EXECUTABLE)
