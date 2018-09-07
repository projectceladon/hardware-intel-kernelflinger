LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libefiusb-$(TARGET_BUILD_VARIANT)
LOCAL_CFLAGS := $(KERNELFLINGER_CFLAGS)
LOCAL_STATIC_LIBRARIES := \
	$(KERNELFLINGER_STATIC_LIBRARIES) \
	libtransport-$(TARGET_BUILD_VARIANT) \
	libkernelflinger-$(TARGET_BUILD_VARIANT)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include/libefiusb
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include/libefiusb
LOCAL_SRC_FILES := \
	usb.c

ifeq ($(KERNELFLINGER_SUPPORT_NON_EFI_BOOT),true)
LOCAL_CFLAGS += -D__SUPPORT_ABL_BOOT
endif

ifneq ($(KERNELFLINGER_SUPPORT_NON_EFI_BOOT),true)
LOCAL_SRC_FILES += \
	device_mode/cpuio.c \
	device_mode/UsbDeviceDxe.c \
	device_mode/UsbDeviceMode.c \
	device_mode/XdciDevice.c \
	device_mode/XdciDWC.c \
	device_mode/XdciTable.c \
	device_mode/XdciUtility.c
endif

include $(BUILD_EFI_STATIC_LIBRARY)
