KERNELFLINGER_LOCAL_PATH := $(call my-dir)
include $(call all-subdir-makefiles)
LOCAL_PATH := $(KERNELFLINGER_LOCAL_PATH)

include $(CLEAR_VARS)

kf_intermediates := $(call intermediates-dir-for,EFI,kernelflinger)

VERITY_CERT := $(kf_intermediates)/verity.cer
KEYSTORE := $(kf_intermediates)/keystore.bin
OEM_KEY := $(kf_intermediates)/oem.key
OEM_CERT := $(kf_intermediates)/oem.cer
PADDED_KEYSTORE := $(kf_intermediates)/keystore.padded.bin
PADDED_OEM_CERT := $(kf_intermediates)/oem.paded.cer

TARGET_OEM_KEY_PAIR ?= device/intel/build/testkeys/oem

$(OEM_CERT): $(TARGET_OEM_KEY_PAIR).x509.pem $(OPENSSL)
	$(transform-pem-cert-to-der-cert)

$(OEM_KEY): $(TARGET_OEM_KEY_PAIR).pk8 $(OPENSSL)
	$(transform-der-key-to-pem-key)

$(PADDED_OEM_CERT): $(OEM_CERT)
	$(call pad-binary, 4096)

#$(VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
#	$(transform-pem-cert-to-der-cert)

$(KEYSTORE): $(OEM_KEY) $(KEYSTORE_SIGNER)
	$(KEYSTORE_SIGNER) $(TARGET_OEM_KEY_PAIR).pk8 $(TARGET_OEM_KEY_PAIR).x509.pem $@

$(PADDED_KEYSTORE): $(KEYSTORE)
	$(call pad-binary, 32768)

$(LOCAL_PATH)/oemkeystore.S: $(PADDED_KEYSTORE) $(PADDED_OEM_CERT)

LOCAL_MODULE := kernelflinger-eng
LOCAL_CFLAGS := -DKERNELFLINGER  -Wall -Wextra -Werror
LOCAL_OBJCOPY_FLAGS := -j .oemkeys
LOCAL_ASFLAGS := -DOEM_KEYSTORE_FILE=\"$(PADDED_KEYSTORE)\" \
	-DOEM_KEY_FILE=\"$(PADDED_OEM_CERT)\"
LOCAL_STATIC_LIBRARIES := libkernelflinger-$(TARGET_BUILD_VARIANT) libcryptlib \
	libopenssl-efi libgnuefi libefi
LOCAL_MODULE_STEM := kernelflinger
LOCAL_SRC_FILES := \
	kernelflinger.c \
	oemkeystore.S \
	ux.c

ifeq ($(TARGET_USE_USERFASTBOOT),true)
    LOCAL_CFLAGS += -DUSERFASTBOOT
else
    LOCAL_STATIC_LIBRARIES += libfastboot-$(TARGET_BUILD_VARIANT)
endif

include $(BUILD_EFI_EXECUTABLE)

