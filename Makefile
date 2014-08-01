ifeq ($(ARCH),x86_64)
ARCH_DIR := linux-x86_64
else
ARCH_DIR := linux-x86
endif

GNU_EFI_TOP := $(ANDROID_BUILD_TOP)/hardware/intel/efi_prebuilts/gnu-efi/$(ARCH_DIR)/
GNU_EFI_INCLUDE := $(GNU_EFI_TOP)/include/efi
GNU_EFI_LIB :=  $(GNU_EFI_TOP)/lib

EFI_LIBS := -lefi -lgnuefi -lopenssl $(shell $(CC) -print-libgcc-file-name)

OPENSSL_TOP := $(ANDROID_BUILD_TOP)/hardware/intel/efi_prebuilts/uefi_shim/$(ARCH_DIR)/
OPENSSL_INCLUDE := $(OPENSSL_TOP)/Include

GUMMIBOOT_KEY_PAIR ?= $(ANDROID_BUILD_TOP)/device/intel/build/testkeys/vendor

CPPFLAGS := -I$(GNU_EFI_INCLUDE) -I$(GNU_EFI_INCLUDE)/$(ARCH) -I$(OPENSSL_INCLUDE)
CFLAGS := -ggdb -O3 -fno-stack-protector -fno-strict-aliasing -fpic \
	 -fshort-wchar -Wall -Werror -mno-red-zone -maccumulate-outgoing-args \
	 -mno-mmx -mno-sse -fno-builtin

ifeq ($(ARCH),x86_64)
# FIXME would like to use -DGNU_EFI_USE_MS_ABI, but that requires GCC 4.7
CFLAGS += -DEFI_FUNCTION_WRAPPER
else
CFLAGS += -m32
endif

LDFLAGS	:= -nostdlib -znocombreloc -T $(GNU_EFI_LIB)/elf_$(ARCH)_efi.lds \
	-shared -Bsymbolic -L$(GNU_EFI_LIB) \
	-L$(OPENSSL_TOP) $(GNU_EFI_LIB)/crt0-efi-$(ARCH).o

OBJS := kernelflinger.o \
	android.o \
	efilinux.o \
	options.o \
	acpi.o \
	security.o \
	lib.o \
	ux.o

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

kernelflinger.efi: kernelflinger.unsigned.efi $(GUMMIBOOT_KEY_PAIR).x509.pem kernelflinger.key
	sbsign --key kernelflinger.key \
		--cert $(GUMMIBOOT_KEY_PAIR).x509.pem \
		--output $@ $<

kernelflinger.key: $(GUMMIBOOT_KEY_PAIR).pk8
	openssl pkcs8 -nocrypt -inform DER -outform PEM -in $^ -out $@

%.unsigned.efi: %.so
	objcopy -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc -j .eh_frame \
		-j .vendor_cert \
		--target=efi-app-$(ARCH) $^ $@

%.debug.efi: %.so
	objcopy -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc -j .eh_frame \
		-j .debug_info -j .debug_abbrev -j .debug_aranges \
		-j .debug_line -j .debug_str -j .debug_ranges \
		--target=efi-app-$(ARCH) $^ $@

kernelflinger.so: $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ -lefi $(EFI_LIBS)

clean:
	rm -f $(OBJS) kernelflinger.so kernelflinger.efi kernelflinger.unsigned.efi kernelflinger.key

