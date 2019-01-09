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

set(CAPSULE_SOURCE CAPSULE4ABL)
set(TARGET_PRODUCT \"standalone\")
set(PRODUCT_MANUFACTURER \"Intel\")
# optional platform: PLATFORM_BROXTON, PLATFORM_ICELAKE
# PLATFORM_TIGERLAKE, PLATFORM_KABYLAKE
set(TARGET_BOARD_PLATFORM PLATFORM_BROXTON)

set(EFIWRAPPER_LIB_DEF
	${CAPSULE_SOURCE}
	${TARGET_BOARD_PLATFOMR}
	PRODUCT_NAME=${TARGET_PRODUCT}
	PRODUCT_MANUFACTURER=${PRODUCT_MANUFACTURER}
	)
if(${LOADER_ARCH} STREQUAL "x86_64")
set(EFIWRAPPER_LIB_DEF ${EFIWRAPPER_LIB_DEF} EFI_FUNCTION_WRAPPER GNU_EFI_USE_MS_ABI)
endif()

# optional drivers
set(LIBEFIWRAPPER_DRIVERS
	s8250mem32
	sdhci_mmc
	dw3
	lpmemmap
	lprtc
	acpi
	cf9
	lifecycle
	abl
	ioc_uart
	heci
	tco_wdt
	mmc_serial
	)
