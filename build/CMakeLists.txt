#
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
# Author: Meng Xianglin <xianglinx.meng@intel.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer
#      in the documentation and/or other materials provided with the
#      distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This file defines bootlogic data structures, try to keep it without
# any external definitions in order to ease export of it.
#

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kernelflinger LANGUAGES C ASM)

set(CMAKE_C_COMPILER clang)
set(CMAKE_ASM_COMPILER clang)

execute_process(
	COMMAND ${CMAKE_C_COMPILER} --version
	OUTPUT_VARIABLE CLANG_VERSION
	OUTPUT_STRIP_TRAILING_WHITESPACE
	)
string(REGEX REPLACE ".*version\ \([0-9]*\.[0-9]*\).*" \\1 CLANG_VERSION ${CLANG_VERSION})
message(STATUS "clang version ${CLANG_VERSION}")

set(LOADER_ARCH x86) # x86_64, x86
set(TARGET_EFI_ARCH_NAME ia32) #x86_64, ia32
set(TOP_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(LIBC_INCLUDE
	${TOP_DIR}/bionic/libc/include
	${TOP_DIR}/bionic/libc/kernel/uapi
	${TOP_DIR}/bionic/libc/kernel/android/uapi
	${TOP_DIR}/bionic/libc/kernel/uapi/asm-x86
	)
set(LIB_EFI_SOURCE ${TOP_DIR}/external-gnu-efi/gnu-efi-3.0)
set(LIB_EFI_INCLUDE
	${LIB_EFI_SOURCE}/inc
	${LIB_EFI_SOURCE}/inc/${TARGET_EFI_ARCH_NAME}
	${LIB_EFI_SOURCE}/inc/protocol)
set(LIB_PAYLOAD_SOURCE ${TOP_DIR}/coreboot/payloads/libpayload)
set(LIB_PAYLOAD_INCLUDE ${LIB_PAYLOAD_SOURCE}/include ${LIB_PAYLOAD_SOURCE}/include/x86 ${CMAKE_CURRENT_BINARY_DIR})
set(EFIWRAPPER_SOURCE ${TOP_DIR}/efiwrapper)
set(EFIWRAPPER_LIB_SOURCE ${EFIWRAPPER_SOURCE}/libefiwrapper)
set(EFIWRAPPER_DRIVER_SOURCE ${EFIWRAPPER_SOURCE}/drivers)
set(KERNELFLINGER_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(LIB_ADB_SOURCE ${KERNELFLINGER_SOURCE}/libadb)
set(LIB_EFITCP_SOURCE ${KERNELFLINGER_SOURCE}/libefitcp)
set(LIB_EFIUSB_SOURCE ${KERNELFLINGER_SOURCE}/libefiusb)
set(LIB_ELFLOADER_SOURCE ${KERNELFLINGER_SOURCE}/libelfloader)
set(LIB_FASTBOOT_SOURCE ${KERNELFLINGER_SOURCE}/libfastboot)
set(LIB_HECI_SOURCE ${KERNELFLINGER_SOURCE}/libheci)
set(LIB_KERNELFLINGER_SOURCE ${KERNELFLINGER_SOURCE}/libkernelflinger)
set(LIB_TRANSPORT_SOURCE ${KERNELFLINGER_SOURCE}/libtransport)

set(GLOBAL_CFLAGS -ggdb -O3 -fno-stack-protector -fno-strict-aliasing -fpic -fshort-wchar
	-mno-red-zone -mno-mmx -fno-builtin -m64 -mstackrealign -mstack-alignment=32 -ffunction-sections
	-ffreestanding -fno-stack-check -Wno-pointer-sign -Wno-address-of-packed-member
	-Wno-macro-redefined -Wno-pointer-bool-conversion -Wno-unused-const-variable
	-Wno-constant-conversion -Wno-unused-function -Wno-tautological-pointer-compare
	)
if(${LOADER_ARCH} STREQUAL "x86")
set(GLOBAL_CFLAGS ${GLOBAL_CFLAGS} -m32)
endif()

set(UBSAN "minimal")
if(${CLANG_VERSION} VERSION_LESS "6.0")
	message(STATUS "clang version less than 6.0: ${CLANG_VERSION}")
	set(GLOBAL_CFLAGS ${GLOBAL_CFLAGS} -Wno-unknown-attributes -Wno-unknown-warning-option)
	set(UBSAN "standalone")
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/sources.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/config.cmake)

foreach(src ${DEPENDENCIES})
	if (NOT EXISTS ${src})
		execute_process(
			COMMAND git clone ${${src}-repo}
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			)
	endif()
endforeach()
execute_process(
		COMMAND git -C coreboot reset --hard 28cee5
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		OUTPUT_QUIET
		)

#libefi
add_library(efi "")
target_sources(efi PRIVATE ${LIB_EFI_SOURCES})
if(${TARGET_EFI_ARCH_NAME} STREQUAL "x86_64")
target_sources(efi PRIVATE
	${LIB_EFI_SOURCE}/lib/${TARGET_EFI_ARCH_NAME}/callwrap.c
	)
endif()
target_include_directories(efi PRIVATE
	${LIB_EFI_SOURCE}/lib
	${LIB_EFI_INCLUDE}
	)
target_compile_options(efi PRIVATE -Wno-error ${GLOBAL_CFLAGS})
if(${LOADER_ARCH} STREQUAL "x86_64")
target_compile_definitions(efi PRIVATE EFI_FUNCTION_WRAPPER GNU_EFI_USE_MS_ABI)
endif()

#libgnuefi
add_library(gnuefi "")
target_sources(gnuefi PRIVATE
	${LIB_EFI_SOURCE}/gnuefi/reloc_${TARGET_EFI_ARCH_NAME}.c
	)
target_include_directories(gnuefi PRIVATE ${LIB_EFI_INCLUDE} ${LIBC_INCLUDE})

#libpayload
add_library(payload "")
target_sources(payload PRIVATE ${LIB_PAYLOAD_SOURCES})
if(${LOADER_ARCH} STREQUAL "x86_64")
	target_sources(payload PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/exception_x64.c)
else()
	target_sources(payload PRIVATE
		${LIB_PAYLOAD_SOURCE}/arch/x86/exec.S
		${LIB_PAYLOAD_SOURCE}/arch/x86/exception_asm.S
		)
endif()
target_compile_options(payload PRIVATE
	${GLOBAL_CFLAGS} -include ${LIB_PAYLOAD_SOURCE}/include/kconfig.h
	)
if(${LOADER_ARCH} STREQUAL "x86_64")
	target_compile_definitions(payload PRIVATE BUILD_X64)
endif()

set(PAYLOAD_CONFIG ${CMAKE_CURRENT_BINARY_DIR}/libpayload-config.h)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/libpayload-config.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(APPEND ${PAYLOAD_CONFIG} "#define CONFIG_LP_BASE_ADDRESS 0x12800000\n")
file(APPEND ${PAYLOAD_CONFIG} "#define CONFIG_LP_HEAP_SIZE 125829120\n")
file(APPEND ${PAYLOAD_CONFIG} "#define CONFIG_LP_STACK_SIZE 1048576\n")
target_include_directories(payload PRIVATE ${LIB_PAYLOAD_INCLUDE})

#libcrt0-libpayload-ia32
add_library(crt0-libpayload-ia32 "")
target_sources(crt0-libpayload-ia32 PRIVATE ${LIB_PAYLOAD_SOURCE}/arch/x86/head.S)
target_compile_options(crt0-libpayload-ia32 PRIVATE ${GLOBAL_CFLAGS})

add_library(efiwrapperlib "")
target_sources(efiwrapperlib PRIVATE ${EFIWRAPPER_LIB_SOURCES})
target_compile_options(efiwrapperlib PRIVATE ${GLOBAL_CFLAGS} -Wall -Wextra)
if(${LOADER_ARCH} STREQUAL "x86_64")
	target_compile_definitions(efiwrapperlib PRIVATE BUILD_X64 __STDC_VERSION__=199901L)
endif()
target_compile_definitions(efiwrapperlib PRIVATE ${EFIWRAPPER_LIB_DEF})
target_include_directories(efiwrapperlib PRIVATE
	${EFIWRAPPER_LIB_SOURCE}
	${EFIWRAPPER_LIB_SOURCE}/../include/libefiwrapper
	${LIB_EFI_INCLUDE}
	)
target_link_libraries(efiwrapperlib efiwrapper_driver)

#libefiwrapper_driver
set(DRIVER_SOURCES "")
set(GENERATED_DRIVER_FILE ${CMAKE_CURRENT_BINARY_DIR}/drivers.c)

add_library(efiwrapper_driver "")
foreach(driver ${LIBEFIWRAPPER_DRIVERS})
	file(GLOB DRIVER_SOURCES ${EFIWRAPPER_DRIVER_SOURCE}/${driver}/*.c)
	target_sources(efiwrapper_driver PRIVATE ${DRIVER_SOURCES})
endforeach()
file(WRITE ${GENERATED_DRIVER_FILE} "#include \"ewdrv.h\"\n")
foreach(drv ${LIBEFIWRAPPER_DRIVERS})
	file(APPEND ${GENERATED_DRIVER_FILE} "#include \"${drv}/${drv}.h\"\n")
endforeach()
file(APPEND ${GENERATED_DRIVER_FILE} "\nstatic ewdrv_t *drivers[] = {\n")
foreach(drv ${LIBEFIWRAPPER_DRIVERS})
	file(APPEND ${GENERATED_DRIVER_FILE} "&${drv}_drv,\n")
endforeach()
file(APPEND ${GENERATED_DRIVER_FILE} "NULL\n};\n\n")
file(APPEND ${GENERATED_DRIVER_FILE} "ewdrv_t **ew_drivers = drivers;")
target_sources(efiwrapper_driver PRIVATE ${GENERATED_DRIVER_FILE})
target_compile_options(efiwrapper_driver PRIVATE ${GLOBAL_CFLAGS} -Wall -Wextra)
if(${LOADER_ARCH} STREQUAL "x86_64")
	target_compile_definitions(efiwrapper_driver PRIVATE BUILD_X64 __STDC_VERSION__=199901L)
endif()
target_compile_definitions(efiwrapper_driver PRIVATE ${EFIWRAPPER_LIB_DEF})
target_include_directories(efiwrapper_driver PRIVATE
	${EFIWRAPPER_DRIVER_SOURCE}
	${EFIWRAPPER_LIB_SOURCE}/../include/hardware
	${EFIWRAPPER_LIB_SOURCE}/../include/libefiwrapper
	${LIB_EFI_INCLUDE}
	${LIB_PAYLOAD_INCLUDE}
	)
target_link_libraries(efiwrapper_driver efiwrapperlib)

#libefiwrapper
add_library(efiwrapper "")
target_sources(efiwrapper PRIVATE ${EFIWRAPPER_SOURCE}/main.c)
target_compile_options(efiwrapper PRIVATE ${GLOBAL_CFLAGS} -Wall -Wextra)
if(${LOADER_ARCH} STREQUAL "x86_64")
	target_compile_definitions(efiwrapper PRIVATE BUILD_X64 __STDC_VERSION__=199901L)
endif()
target_compile_definitions(efiwrapper PRIVATE ${EFIWRAPPER_LIB_DEF})
target_include_directories(efiwrapper PRIVATE
	${EFIWRAPPER_LIB_SOURCE}/../include/libefiwrapper
	${LIB_EFI_INCLUDE}
	${LIB_PAYLOAD_INCLUDE}
	)

set(KERNELFLINGER_CFLAGS -Wall -Wextra -mrdrnd)
set(KERNELFLINGER_DEF
	USE_SLOT
	FASTBOOT_FOR_NON_ANDROID
	)

#libadb
add_library(adb "")
target_sources(adb PRIVATE ${LIB_ADB_SOURCES})
target_compile_options(adb PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(adb PRIVATE ${KERNELFLINGER_DEF})
if(${LOADER_ARCH} STREQUAL "x86_64")
	target_compile_definitions(adb PRIVATE __STDC_VERSION__=199901L ARCH_X86_64=1)
endif()
target_include_directories(adb PRIVATE
	${LIB_ADB_SOURCE}/../include/libadb
	${LIB_ADB_SOURCE}/../include/libkernelflinger
	${LIB_ADB_SOURCE}/../include/libefiusb
	${LIB_ADB_SOURCE}/../include/libefitcp
	${LIB_ADB_SOURCE}/../include/libtransport
	${LIB_EFI_INCLUDE}
	${LIB_PAYLOAD_INCLUDE}
	)

#libefitcp
add_library(efitcp "")
target_sources(efitcp PRIVATE ${LIB_EFITCP_SOURCE}/tcp.c)
target_compile_options(efitcp PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(efitcp PRIVATE ${KERNELFLINGER_DEF})
target_include_directories(efitcp PRIVATE
	${LIB_EFITCP_SOURCE}/../include/libefitcp
	${LIB_EFITCP_SOURCE}/../include/libkernelflinger
	${LIB_EFITCP_SOURCE}/../include/libtransport
	${LIB_EFI_INCLUDE}
	${LIB_PAYLOAD_INCLUDE}
	)

#libefiusb
add_library(efiusb "")
target_sources(efiusb PRIVATE ${LIB_EFIUSB_SOURCE}/usb.c)
target_compile_options(efiusb PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(efiusb PRIVATE ${KERNELFLINGER_DEF})
target_include_directories(efiusb PRIVATE
	${LIB_EFIUSB_SOURCE}/../include/libefiusb
	${LIB_EFIUSB_SOURCE}/../include/libkernelflinger
	${LIB_EFIUSB_SOURCE}/../include/libtransport
	${LIB_EFI_INCLUDE}
	)

#libelfloader
add_library(elfloader "")
target_sources(elfloader PRIVATE ${LIB_ELFLOADER_SOURCES})
target_compile_options(elfloader PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(elfloader PRIVATE ${KERNELFLINGER_DEF})
target_include_directories(elfloader PRIVATE
	${LIB_ELFLOADER_SOURCE}/include
	${LIB_ELFLOADER_SOURCE}/../include/libkernelflinger
	${LIB_EFI_INCLUDE}
	)

#libfastboot
add_library(fastboot "")
target_sources(fastboot PRIVATE ${LIB_FASTBOOT_SOURCES})
target_compile_options(fastboot PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(fastboot PRIVATE
	${KERNELFLINGER_DEF}
	TARGET_BOOTLOADER_BOARD_NAME=${TARGET_PRODUCT}
	__SUPPORT_ABL_BOOT
	)
target_include_directories(fastboot PRIVATE
	${LIB_FASTBOOT_SOURCE}/../include/libfastboot
	${LIB_FASTBOOT_SOURCE}/../include/libefiusb
	${LIB_FASTBOOT_SOURCE}/../include/libefitcp
	${LIB_FASTBOOT_SOURCE}/../include/libkernelflinger
	${LIB_FASTBOOT_SOURCE}/../include/libtransport
	${LIB_EFI_INCLUDE}
	${LIBC_INCLUDE}
	)

#libheci
add_library(heci "")
target_sources(heci PRIVATE ${LIB_HECI_SOURCE}/hecisupport.c)
target_compile_options(heci PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(heci PRIVATE ${KERNELFLINGER_DEF})
target_include_directories(heci PRIVATE
	${LIB_HECI_SOURCE}/../include/libheci
	${LIB_HECI_SOURCE}/../include/libkernelflinger
	${LIB_EFI_INCLUDE}
	)

#libkernelflinger
add_library(kernelflinger "")
target_sources(kernelflinger PRIVATE ${LIB_KERNELFLINGER_SOURCES})
target_compile_options(kernelflinger PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(kernelflinger PRIVATE
	${KERNELFLINGER_DEF}
	TARGET_BOOTLOADER_BOARD_NAME=${TARGET_PRODUCT}
	ALLOW_UNSUPPORTED_ACPI_TABLE
	USE_WATCHDOG
	IGNORE_NOT_APPLICABLE_RESET
	__SUPPORT_ABL_BOOT
	)
if(${LOADER_ARCH} STREQUAL "x86_64")
target_compile_definitions(kernelflinger PRIVATE
	EFI_FUNCTION_WRAPPER
	GNU_EFI_USE_MS_ABI
	)
endif()
target_include_directories(kernelflinger PRIVATE
	${LIB_KERNELFLINGER_SOURCE}
	${LIB_KERNELFLINGER_SOURCE}/../include/libkernelflinger
	${LIB_KERNELFLINGER_SOURCE}/../
	${LIB_KERNELFLINGER_SOURCE}/../libefiusb/protocol
	${LIB_EFI_INCLUDE}
	${LIBC_INCLUDE}
	)

add_library(transport "")
target_sources(transport PRIVATE ${LIB_TRANSPORT_SOURCE}/transport.c)
target_compile_options(transport PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(transport PRIVATE ${KERNELFLINGER_DEF})
target_include_directories(transport PRIVATE
	${LIB_TRANSPORT_SOURCE}/../include/libtransport
	${LIB_TRANSPORT_SOURCE}/../include/libkernelflinger
	${LIB_EFI_INCLUDE}
	)

add_executable(fastboot.sym.elf "")
target_sources(fastboot.sym.elf PRIVATE
	${KERNELFLINGER_SOURCE}/kf4abl.c
	)
target_compile_options(fastboot.sym.elf PRIVATE ${GLOBAL_CFLAGS} ${KERNELFLINGER_CFLAGS})
target_compile_definitions(fastboot.sym.elf PRIVATE
	${KERNELFLINGER_DEF}
	__SUPPORT_ABL_BOOT
	__FORCE_FASTBOOT
	)
if(${LOADER_ARCH} STREQUAL "x86_64")
target_compile_definitions(fastboot.sym.elf PRIVATE
	EFI_FUNCTION_WRAPPER
	GNU_EFI_USE_MS_ABI
	)
endif()

target_include_directories(fastboot.sym.elf PRIVATE
	${KERNELFLINGER_SOURCE}/libkernelflinger
	${KERNELFLINGER_SOURCE}/include/libfastboot
	${KERNELFLINGER_SOURCE}/include/libkernelflinger
	${KERNELFLINGER_SOURCE}/include/libheci
	${LIB_EFI_INCLUDE}
	${LIBC_INCLUDE}
	)

target_link_libraries(fastboot.sym.elf
	-nostdlib
	-Wl,-no-undefined,-fatal-warnings,-gc-sections
	-Wl,-Bsymbolic,-znocombreloc,-znoexecstack,-zrelro,-znow,-static
	-Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/elf_ia32_abl.lds
	-Wl,-zmax-page-size=0x1000
	-Wl,-defsym=CONFIG_LP_BASE_ADDRESS=0x12800000
	-Wl,-defsym=CONFIG_LP_HEAP_SIZE=125829120
	-Wl,-defsym=CONFIG_LP_STACK_SIZE=1048576
	-Wl,-whole-archive crt0-libpayload-${TARGET_EFI_ARCH_NAME} -Wl,-no-whole-archive
	-Wl,-start-group
	fastboot
	efiusb
	efitcp
	transport
	heci
	gnuefi
	efi
	kernelflinger
	payload
	efiwrapperlib
	efiwrapper_driver
	efiwrapper
	elfloader
	adb
	/usr/lib/clang/${CLANG_VERSION}/lib/linux/libclang_rt.ubsan_${UBSAN}-x86_64.a
	-Wl,-end-group
	/usr/lib/clang/${CLANG_VERSION}/lib/linux/libclang_rt.builtins-i386.a
	-Wl,-Map=fastboot.map
	)
