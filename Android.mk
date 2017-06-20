KERNELFLINGER_LOCAL_PATH := $(call my-dir)
KERNELFLINGER_CFLAGS := -Wall -Wextra -Werror -mrdrnd

ifeq ($(TARGET_USE_TRUSTY),true)
    KERNELFLINGER_CFLAGS += -DUSE_TRUSTY
endif

ifeq ($(TARGET_USE_MULTIBOOT),true)
    KERNELFLINGER_CFLAGS += -DUSE_MULTIBOOT
endif

ifeq ($(IOC_USE_SLCAN),true)
    KERNELFLINGER_CFLAGS += -DIOC_USE_SLCAN
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

#Enable android verifed boot support(libavb)
ifeq ($(BOARD_AVB_ENABLE),true)
    KERNELFLINGER_CFLAGS += -DUSE_AVB
    ifeq ($(TARGET_BUILD_VARIANT),userdebug)
          KERNELFLINGER_CFLAGS += -DAVB_ENABLE_DEBUG
    endif
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

ifeq ($(KERNELFLINGER_SUPPORT_ABL_BOOT),true)
    LOCAL_CFLAGS += -D__SUPPORT_ABL_BOOT
endif

ifeq ($(KERNELFLINGER_DISABLE_DEBUG_PRINT),true)
    LOCAL_CFLAGS += -D__DISABLE_DEBUG_PRINT
endif

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

ifeq ($(BOARD_AVB_ENABLE),true)
    LOCAL_STATIC_LIBRARIES += libavb_kernelflinger-$(TARGET_BUILD_VARIANT)
endif
ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_STATIC_LIBRARIES += libadb-$(TARGET_BUILD_VARIANT)
endif
LOCAL_SRC_FILES := \
	kf4abl.c

ifeq ($(BOARD_AVB_ENABLE),true)
LOCAL_SRC_FILES	+= \
	avb_init.c
endif

ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY), true)
kf4abl_intermediates := $(call intermediates-dir-for,ABL,kf4abl)

ABL_VERITY_CERT := $(kf4abl_intermediates)/verity.cer
ABL_PADDED_VERITY_CERT := $(kf4abl_intermediates)/verity.padded.cer
ABL_OEMCERT_OBJ := $(kf4abl_intermediates)/oemcert.o

$(ABL_VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
	$(transform-pem-cert-to-der-cert)

$(ABL_PADDED_VERITY_CERT): $(ABL_VERITY_CERT)
	$(call pad-binary, 4096)

ifeq ($(TARGET_IAFW_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

abl_sym_binary := $(shell echo _binary_$(ABL_PADDED_VERITY_CERT) | sed "s/[\/\.-]/_/g")
$(ABL_OEMCERT_OBJ): $(ABL_PADDED_VERITY_CERT)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(abl_sym_binary)_start=_binary_oemcert_start \
                       --redefine-sym $(abl_sym_binary)_end=_binary_oemcert_end \
                       --redefine-sym $(abl_sym_binary)_size=_binary_oemcert_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES := $(ABL_OEMCERT_OBJ)
endif

ifeq ($(BOARD_AVB_ENABLE), true)
kf4abl_intermediates := $(call intermediates-dir-for,ABL,kf4abl)

ABL_AVB_PK := $(kf4abl_intermediates)/avb_pk.bin
ABL_PADDED_AVB_PK := $(kf4abl_intermediates)/avb_pk.padded.bin
ABL_AVB_PK_OBJ := $(kf4abl_intermediates)/avb_pk.o
ifndef BOARD_AVB_KEY_PATH
BOOTLOADER_AVB_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
else
BOOTLOADER_AVB_KEY_PATH := $(BOARD_AVB_KEY_PATH)
endif

$(ABL_AVB_PK): $(BOOTLOADER_AVB_KEY_PATH) avbtool
	avbtool extract_public_key --key $< --output $@

$(ABL_PADDED_AVB_PK): $(ABL_AVB_PK)
	$(call pad-binary, 4096)

ifeq ($(TARGET_IAFW_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

avb_sym_binary := $(shell echo _binary_$(ABL_PADDED_AVB_PK) | sed "s/[\/\.-]/_/g")
$(ABL_AVB_PK_OBJ): $(ABL_PADDED_AVB_PK)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(avb_sym_binary)_start=_binary_avb_pk_start \
                       --redefine-sym $(avb_sym_binary)_end=_binary_avb_pk_end \
                       --redefine-sym $(avb_sym_binary)_size=_binary_avb_pk_size \
                       --rename-section .data=.avbkeys $@ $@

LOCAL_GENERATED_SOURCES += $(ABL_AVB_PK_OBJ)
LOCAL_C_INCLUDES := \
	$(addprefix $(LOCAL_PATH)/,avb)
endif
include $(BUILD_ABL_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := fb4abl-$(TARGET_BUILD_VARIANT)
LOCAL_MODULE_STEM := fb4abl
LOCAL_CFLAGS := $(SHARED_CFLAGS)

ifeq ($(KERNELFLINGER_SUPPORT_ABL_BOOT),true)
    LOCAL_CFLAGS += -D__SUPPORT_ABL_BOOT
endif

LOCAL_CFLAGS += -D__FORCE_FASTBOOT

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
fb4abl_intermediates := $(call intermediates-dir-for,ABL,fb4abl)

FB_ABL_VERITY_CERT := $(fb4abl_intermediates)/verity.cer
FB_ABL_PADDED_VERITY_CERT := $(fb4abl_intermediates)/verity.padded.cer
FB_ABL_OEMCERT_OBJ := $(fb4abl_intermediates)/oemcert.o

$(FB_ABL_VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
	$(transform-pem-cert-to-der-cert)

$(FB_ABL_PADDED_VERITY_CERT): $(FB_ABL_VERITY_CERT)
	$(call pad-binary, 4096)

fb_abl_sym_binary := $(shell echo _binary_$(FB_ABL_PADDED_VERITY_CERT) | sed "s/[\/\.-]/_/g")
$(FB_ABL_OEMCERT_OBJ): $(FB_ABL_PADDED_VERITY_CERT)
	mkdir -p $(@D) && \
	$(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) --binary-architecture i386 $< $@ && \
	$(EFI_OBJCOPY) --redefine-sym $(fb_abl_sym_binary)_start=_binary_oemcert_start \
                       --redefine-sym $(fb_abl_sym_binary)_end=_binary_oemcert_end \
                       --redefine-sym $(fb_abl_sym_binary)_size=_binary_oemcert_size \
                       --rename-section .data=.oemkeys $@ $@

LOCAL_GENERATED_SOURCES := $(FB_ABL_OEMCERT_OBJ)
include $(BUILD_ABL_EXECUTABLE)

