LIBKERNELFLINGER_LOCAL_PATH := $(call my-dir)
include $(call all-subdir-makefiles)
LOCAL_PATH := $(LIBKERNELFLINGER_LOCAL_PATH)

include $(CLEAR_VARS)

PNG2C := $(HOST_OUT_EXECUTABLES)/png2c$(HOST_EXECUTABLE_SUFFIX)
GEN_FONTS := $(LOCAL_PATH)/tools/gen_fonts.sh

res_intermediates := $(call intermediates-dir-for,STATIC_LIBRARIES,libkernelflinger)

font_res := $(res_intermediates)/res/font_res.h
img_res := $(res_intermediates)/res/img_res.h

$(LOCAL_PATH)/ui_font.c: $(font_res)
$(LOCAL_PATH)/ui_image.c: $(img_res)

ifndef TARGET_KERNELFLINGER_IMAGES_DIR
TARGET_KERNELFLINGER_IMAGES_DIR := $(LOCAL_PATH)/res/images
endif
ifndef TARGET_KERNELFLINGER_FONT_DIR
TARGET_KERNELFLINGER_FONT_DIR := $(LOCAL_PATH)/res/fonts
endif

KERNELFLINGER_IMAGES := $(wildcard $(TARGET_KERNELFLINGER_IMAGES_DIR)/*.png)
KERNELFLINGER_FONTS := $(wildcard $(TARGET_KERNELFLINGER_FONT_DIR)/*.png)

$(img_res): $(KERNELFLINGER_IMAGES)
	$(hide) mkdir -p $(dir $@)
	$(hide) echo "/* Do not modify this auto-generated file. */" > $@
	$(hide) $(foreach file,$(KERNELFLINGER_IMAGES),\
         echo "extern uint8_t _binary_"$(subst .,_,$(notdir $(file)))"_start;" >> $@;)
	$(hide) $(foreach file,$(KERNELFLINGER_IMAGES),\
         echo "extern uint32_t _binary_"$(subst .,_,$(notdir $(file)))"_size;" >> $@;)
	$(hide) echo "ui_image_t ui_images[] = {" >> $@
	$(hide) $(foreach file,$(KERNELFLINGER_IMAGES),\
         echo "{ .name = \""$(subst .png,,$(notdir $(file)))"\", "\
		".data = (UINT8 *)&_binary_"$(subst .,_,$(notdir $(file)))"_start, "\
		".size = (UINTN)&_binary_"$(subst .,_,$(notdir $(file)))"_size}," >> $@;)
	$(hide) echo "};" >> $@

$(font_res): $(KERNELFLINGER_FONTS) $(PNG2C) $(GEN_FONTS)
	$(hide) mkdir -p $(dir $@)
	$(hide) export PATH=$(HOST_OUT_EXECUTABLES):$$PATH; $(GEN_FONTS) $(TARGET_KERNELFLINGER_FONT_DIR) $@

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    ELF_OUTPUT := elf64-x86-64
else
    ELF_OUTPUT := elf32-i386
endif

$(res_intermediates)/%.o: $(TARGET_KERNELFLINGER_IMAGES_DIR)/%.png
	$(hide) $(EFI_OBJCOPY) --input binary --output $(ELF_OUTPUT) \
		--binary-architecture i386 $< $@
	$(eval $@_old := $(subst .,_,$(subst /,_,$<)))
	$(eval $@_new := $(subst .,_,$(notdir $<)))
	$(hide) $(EFI_OBJCOPY) \
		--redefine-sym _binary_$($@_old)_start=_binary_$($@_new)_start \
		--redefine-sym _binary_$($@_old)_end=_binary_$($@_new)_end \
		--redefine-sym _binary_$($@_old)_size=_binary_$($@_new)_size \
	        $@ $@

LOCAL_MODULE := libkernelflinger-$(TARGET_BUILD_VARIANT)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libkernelflinger
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS) \
                -DTARGET_BOOTLOADER_BOARD_NAME=\"$(TARGET_BOOTLOADER_BOARD_NAME)\"
LOCAL_STATIC_LIBRARIES := $(KERNELFLINGER_STATIC_LIBRARIES)

ifeq ($(TARGET_USE_TPM),true)
    LOCAL_STATIC_LIBRARIES += libedk2_tpm
endif

ifeq ($(KERNELFLINGER_ALLOW_UNSUPPORTED_ACPI_TABLE),true)
    LOCAL_CFLAGS += -DALLOW_UNSUPPORTED_ACPI_TABLE
endif

ifeq ($(KERNELFLINGER_USE_WATCHDOG),true)
    LOCAL_CFLAGS += -DUSE_WATCHDOG
endif

ifeq ($(KERNELFLINGER_USE_CHARGING_APPLET),true)
    LOCAL_CFLAGS += -DUSE_CHARGING_APPLET
endif

ifneq ($(KERNELFLINGER_IGNORE_RSCI),true)
    LOCAL_CFLAGS += -DUSE_RSCI
endif

ifeq ($(KERNELFLINGER_IGNORE_NOT_APPLICABLE_RESET),true)
    LOCAL_CFLAGS += -DIGNORE_NOT_APPLICABLE_RESET
endif

ifeq ($(KERNELFLINGER_DISABLE_DEBUG_PRINT),true)
    LOCAL_CFLAGS += -D__DISABLE_DEBUG_PRINT
endif

ifeq ($(KERNELFLINGER_USE_IPP_SHA256),true)
    LOCAL_CFLAGS += -DUSE_IPP_SHA256
    LOCAL_CFLAGS += -msse4 -msha
endif

ifneq ($(KERNELFLINGER_FIXED_RPMB_KEY),)
    LOCAL_CFLAGS += -DFIXED_RPMB_KEY=$(KERNELFLINGER_FIXED_RPMB_KEY)
endif

LOCAL_SRC_FILES := \
	android.c \
	efilinux.c \
	acpi.c \
	acpi_image.c \
	lib.c \
	options.c \
	security.c \
	vars.c \
	log.c \
	em.c \
	gpt.c \
	storage.c \
	pci.c \
	mmc.c \
	ufs.c \
	sdcard.c \
	sdio.c \
	sata.c \
	uefi_utils.c \
	targets.c \
	smbios.c \
	oemvars.c \
	text_parser.c \
	watchdog.c \
	life_cycle.c \
	qsort.c \
	rpmb/rpmb.c \
	rpmb/rpmb_emmc.c \
	rpmb/rpmb_ufs.c \
	rpmb/rpmb_virtual.c \
	rpmb/rpmb_nvme.c \
	rpmb/rpmb_storage_common.c \
	timer.c \
	nvme.c \
	virtual_media.c \
	general_block.c \
	aes_gcm.c \
	vbmeta_ias.c

ifeq ($(KERNELFLINGER_SUPPORT_USB_STORAGE),true)
	LOCAL_SRC_FILES += usb_storage.c \
			   UsbMassBot.c
endif

ifneq (,$(filter true,$(IOC_USE_SLCAN) $(IOC_USE_CBC)))
	LOCAL_SRC_FILES += ioc_can.c
endif

ifneq ($(BOARD_AVB_ENABLE),true)
	LOCAL_SRC_FILES += \
	signature.c \
	android_vb1.c \
	security_vb1.c
else
	LOCAL_SRC_FILES += \
	android_vb2.c \
	security_vb2.c
endif

ifeq ($(BOARD_GPIO_ENABLE),true)
    LOCAL_SRC_FILES += gpio.c
endif

ifeq ($(BOARD_AVB_ENABLE),true)
ifeq ($(TARGET_USE_ACPIO),true)
LOCAL_CFLAGS += -DBOARD_ACPIOIMAGE_PARTITION_SIZE=$(BOARD_ACPIOIMAGE_PARTITION_SIZE)
endif
ifeq ($(TARGET_USE_ACPI),true)
LOCAL_CFLAGS += -DBOARD_ACPIIMAGE_PARTITION_SIZE=$(BOARD_ACPIIMAGE_PARTITION_SIZE)
endif

ifeq ($(BOARD_SLOT_AB_ENABLE),true)
    LOCAL_SRC_FILES += slot_avb.c
else
    LOCAL_SRC_FILES += slot.c
endif
else
    LOCAL_SRC_FILES += slot.c
endif

ifeq ($(KERNELFLINGER_USE_IPP_SHA256),true)
    LOCAL_SRC_FILES += sha256_ipps.c
endif

ifeq ($(TARGET_USE_TPM),true)
    LOCAL_SRC_FILES += tpm2_security.c
endif

ifneq ($(strip $(KERNELFLINGER_USE_UI)),false)
    LOCAL_SRC_FILES += \
	ui.c \
	ui_color.c \
	ui_font.c \
	ui_textarea.c \
	ui_image.c \
	upng.c \
	ui_boot_menu.c \
	ui_confirm.c
    LOCAL_GENERATED_SOURCES := \
        $(foreach file,$(KERNELFLINGER_IMAGES),\
	    $(res_intermediates)/$(notdir $(file:png=o)))
else
    LOCAL_SRC_FILES += \
	no_ui.c \
	ui_color.c
endif

ifeq ($(HAL_AUTODETECT),true)
    LOCAL_SRC_FILES += blobstore.c
endif

ifeq ($(TARGET_USE_TRUSTY),true)
    LOCAL_SRC_FILES += trusty_common.c
ifeq ($(KERNELFLINGER_TRUSTY_PLATFORM),sbl)
    LOCAL_SRC_FILES += trusty_sbl.c
else
ifeq ($(KERNELFLINGER_TRUSTY_PLATFORM),abl)
    LOCAL_SRC_FILES += trusty_abl.c
else
ifeq ($(KERNELFLINGER_TRUSTY_PLATFORM),vsbl)
    LOCAL_SRC_FILES += trusty_vsbl.c
else
    LOCAL_SRC_FILES += trusty_efi.c
endif
endif
endif
endif

ifeq ($(KERNELFLINGER_SECURITY_PLATFORM),abl)
    LOCAL_SRC_FILES += security_abl.c
else
ifeq ($(KERNELFLINGER_SECURITY_PLATFORM),sbl)
    LOCAL_SRC_FILES += security_sbl.c
else
ifeq ($(KERNELFLINGER_SECURITY_PLATFORM),vsbl)
    LOCAL_SRC_FILES += security_vsbl.c
else
    LOCAL_SRC_FILES += security_efi.c
endif
endif
endif #KERNELFLINGER_SECURITY_PLATFORM

ifneq ($(TARGET_UEFI_ARCH),x86_64)
    LOCAL_SRC_FILES += pae.c
endif

ifeq ($(TARGET_BOOT_SIGNER),)
ifneq ($(BOARD_AVB_ENABLE), true)
    LOCAL_SRC_FILES += \
	aosp_sig.c \
	asn1.c
endif
else
    LOCAL_SRC_FILES += $(TARGET_BOOT_SIGNER)_sig.c
endif

ifeq ($(KERNELFLINGER_USE_RPMB),true)
    LOCAL_SRC_FILES += rpmb/rpmb_storage.c
else  # KERNELFLINGER_USE_RPMB == false
ifeq ($(KERNELFLINGER_USE_RPMB_SIMULATE),true)
    LOCAL_SRC_FILES += rpmb/rpmb_storage.c
endif
endif  # KERNELFLINGER_USE_RPMB

ifeq ($(BOARD_FIRSTSTAGE_MOUNT_ENABLE)|$(filter true, $(TARGET_USE_ACPI) $(TARGET_USE_ACPIO)),true|)
    LOCAL_CFLAGS += -DUSE_FIRSTSTAGE_MOUNT
    LOCAL_SRC_FILES += firststage_mount.c
    IASL := $(INTEL_PATH_BUILD)/acpi-tools/linux64/bin/iasl
    GEN := $(res_intermediates)/firststage_mount_cfg.h
    IASL_CFLAGS := $(filter -D%,$(subst -D ,-D,$(strip $(LOCAL_CFLAGS))))
    LOCAL_GENERATED_SOURCES += $(GEN)

$(GEN): $(FIRST_STAGE_MOUNT_CFG_FILE)
	$(hide) $(IASL) -p $(@:.h=) $(IASL_CFLAGS) -tc $<
	$(hide) mv $(@:.h=.hex) $@
endif # BOARD_FIRSTSTAGE_MOUNT_ENABLE not TARGET_USE_ACPI not TARGET_USE_ACPIO

ifeq ($(BOARD_DISK_BUS),ff.ff)
    LOCAL_CFLAGS += -DAUTO_DISKBUS
endif

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include/libkernelflinger \
		$(LOCAL_PATH)/../ \
		$(LOCAL_PATH)/../avb \
		$(LOCAL_PATH)/../libefiusb/protocol \
		$(res_intermediates)

ifeq ($(BOARD_AVB_ENABLE),true)
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../avb
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../avb/libavb
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../avb/libavb_ab
ifeq ($(BUILD_ANDROID_THINGS),true)
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../avb/libavb_atx
endif
endif
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include/libqltipc
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include/libheci
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include/libelfloader
include $(BUILD_EFI_STATIC_LIBRARY)
