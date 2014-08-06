#
# This script is used to generate gnu_efi prebuilts for both ia32 and x86_64.
# The resulting binaries will be copied into prebuilts/{ia32, x86_64}.
#
# Please make sure you have Android's build system setup first, and lunch
# target defined.

# Specify "-a" in command line to add these prebuilt binaries for
# git commit.
#
# Note:
# 1. ARCH ia32 and x86 are interchangable here.
#    Android uses x86, but EFI uses ia32.
#

set -e

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "[ERROR] \$ANDROID_BUILD_TOP not set, please run lunch"
    exit 2
fi

PREBUILT_TOP=$ANDROID_BUILD_TOP/hardware/intel/efi_prebuilts/

copy_to_prebuilts()
{
    cp -v kernelflinger.db.efi kernelflinger.vendor.efi libkernelflinger.a $PREBUILT_TOP/kernelflinger/linux-$1/
}

copy_insecure_to_prebuilts()
{
    cp -v kernelflinger.unsigned.efi $PREBUILT_TOP/kernelflinger/linux-$1/kernelflinger.insecure.efi
}

add_prebuilts=0
while getopts "a" opt; do
    case "$opt" in
        a) add_prebuilts=1;;
    esac
done

# Check gnu-efi prebuilts are in place
NEEDED_FILES=" \
    gnu-efi/linux-x86_64/lib/crt0-efi-x86_64.o \
    gnu-efi/linux-x86_64/lib/libefi.a
    gnu-efi/linux-x86_64/lib/libgnuefi.a \
    gnu-efi/linux-x86_64/lib/elf_x86_64_efi.lds \
    gnu-efi/linux-x86/lib/crt0-efi-ia32.o \
    gnu-efi/linux-x86/lib/libefi.a
    gnu-efi/linux-x86/lib/libgnuefi.a \
    gnu-efi/linux-x86/lib/elf_ia32_efi.lds \
    "
have_all_files=1
for file in $NEEDED_FILES; do
    if [ ! -s "$PREBUILT_TOP/$file" ]; then
        echo "[ERROR] --- $file does not exists in $PREBUILT_TOP."
        have_all_files=0
    fi
done
if [ "$have_all_files" == "0" ]; then
    echo "[ERROR] *** Please generate all necessary prebuilt binaries under external/gnu-efi before building kernelflinger."
    echo "[ERROR] *** Dependencies not satisfied. aborting..."
    exit 1
fi

# Clean up everything and create prebuilts directory
mkdir -p $PREBUILT_TOP/kernelflinger/linux-x86
mkdir -p $PREBUILT_TOP/kernelflinger/linux-x86_64

MAKE_CMD="make -j8"

$MAKE_CMD ARCH=x86_64 clean
$MAKE_CMD ARCH=ia32 clean

# FIXME remove CC definition and use a host compiler

# Generate prebuilts for x86_64
$MAKE_CMD ARCH=x86_64 \
    CC=$ANDROID_BUILD_TOP/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.7-4.6/bin/x86_64-linux-gcc \
    kernelflinger.db.efi kernelflinger.vendor.efi libkernelflinger.a
copy_to_prebuilts x86_64
$MAKE_CMD ARCH=x86_64 clean

$MAKE_CMD ARCH=x86_64 INSECURE_LOADER=1 \
    CC=$ANDROID_BUILD_TOP/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.7-4.6/bin/x86_64-linux-gcc \
    kernelflinger.unsigned.efi
copy_insecure_to_prebuilts x86_64
$MAKE_CMD ARCH=x86_64 clean

# Generate prebuilts for ia32
$MAKE_CMD ARCH=ia32 \
    CC=$ANDROID_BUILD_TOP//prebuilts/gcc/linux-x86/host/i686-linux-glibc2.7-4.6/bin/i686-linux-gcc \
    kernelflinger.db.efi kernelflinger.vendor.efi libkernelflinger.a
copy_to_prebuilts x86
$MAKE_CMD ARCH=ia32 clean

$MAKE_CMD ARCH=ia32 INSECURE_LOADER=1 \
    CC=$ANDROID_BUILD_TOP//prebuilts/gcc/linux-x86/host/i686-linux-glibc2.7-4.6/bin/i686-linux-gcc \
    kernelflinger.unsigned.efi
copy_insecure_to_prebuilts x86
$MAKE_CMD ARCH=ia32 clean

rm -rf $PREBUILT_TOP/kernelflinger/include
cp -rf include $PREBUILT_TOP/kernelflinger

