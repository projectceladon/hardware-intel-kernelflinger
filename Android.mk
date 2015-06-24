KERNELFLINGER_LOCAL_PATH := $(call my-dir)
KERNELFLINGER_CFLAGS := -Wall -Wextra -Werror -DKERNELFLINGER

ifeq ($(TARGET_BUILD_VARIANT),user)
    KERNELFLINGER_CFLAGS += -DUSER -DUSERDEBUG
endif

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    KERNELFLINGER_CFLAGS += -DUSERDEBUG
endif

ifeq ($(TARGET_NO_DEVICE_UNLOCK),true)
    KERNELFLINGER_CFLAGS += -DNO_DEVICE_UNLOCK
endif

ifeq ($(HAL_AUTODETECT),true)
    KERNELFLINGER_CFLAGS += -DHAL_AUTODETECT
endif

ifeq ($(TARGET_USE_USERFASTBOOT),true)
    KERNELFLINGER_CFLAGS += -DUSERFASTBOOT
endif

KERNELFLINGER_STATIC_LIBRARIES := \
	libcryptlib \
	libopenssl-efi \
	libgnuefi \
	libefi

include $(call all-subdir-makefiles)
LOCAL_PATH := $(KERNELFLINGER_LOCAL_PATH)

SHARED_CFLAGS := $(KERNELFLINGER_CFLAGS)
SHARED_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

include $(CLEAR_VARS)

kf_intermediates := $(call intermediates-dir-for,EFI,kernelflinger)

VERITY_CERT := $(kf_intermediates)/verity.cer
KEYSTORE := $(PRODUCT_OUT)/keystore-testkey.bin
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

# Have to do it this way, keystore_signer wants the raw DER public key and not
# a DER x509 certificate
$(VERITY_CERT): $(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_VERITY_SIGNING_KEY).x509.pem $(OPENSSL)
	@echo "Verity DER public key:  $(notdir $@) <= $(notdir $<)"
	$(hide) mkdir -p $(dir $@)
	$(hide) $(OPENSSL) x509 -in $< -pubkey -noout | openssl enc -base64 -d > $@

$(KEYSTORE): \
		$(TARGET_OEM_KEY_PAIR).pk8 \
		$(TARGET_OEM_KEY_PAIR).x509.pem \
		$(VERITY_CERT) \
		$(KEYSTORE_SIGNER)
	$(KEYSTORE_SIGNER) $(TARGET_OEM_KEY_PAIR).pk8 $(TARGET_OEM_KEY_PAIR).x509.pem $@ $(VERITY_CERT)

$(PADDED_KEYSTORE): $(KEYSTORE)
	$(call pad-binary, 32768)

$(LOCAL_PATH)/oemkeystore.S: $(PADDED_KEYSTORE) $(PADDED_OEM_CERT)

LOCAL_SRC_FILES := \
	kernelflinger.c \
	oemkeystore.S \
	ux.c

ifneq ($(TARGET_USE_USERFASTBOOT),true)
    LOCAL_STATIC_LIBRARIES += libfastboot-$(TARGET_BUILD_VARIANT)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_SRC_FILES += unittest.c
endif

LOCAL_MODULE := kernelflinger-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_OBJCOPY_FLAGS := -j .oemkeys
LOCAL_ASFLAGS := -DOEM_KEYSTORE_FILE=\"$(PADDED_KEYSTORE)\" \
	-DOEM_KEY_FILE=\"$(PADDED_OEM_CERT)\"
LOCAL_STATIC_LIBRARIES += $(SHARED_STATIC_LIBRARIES)
LOCAL_MODULE_STEM := kernelflinger

include $(BUILD_EFI_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := installer-$(TARGET_BUILD_VARIANT)
LOCAL_STATIC_LIBRARIES := \
	$(SHARED_STATIC_LIBRARIES) \
	libfastboot-for-installer-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(SHARED_CFLAGS)
LOCAL_SRC_FILES := installer.c
LOCAL_MODULE_STEM := installer
LOCAL_C_INCLUDES := $(addprefix $(LOCAL_PATH)/,libfastboot)
include $(BUILD_EFI_EXECUTABLE)

