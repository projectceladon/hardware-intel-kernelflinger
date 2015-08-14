/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
 *         Jeremy Compostella <jeremy.compostella@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <efi.h>
#include <efiapi.h>

#include "keystore.h"
#include "vars.h"
#include "ui.h"
#include "lib.h"
#include "smbios.h"
#include "version.h"

#define OFF_MODE_CHARGE_VAR	L"off-mode-charge"
#define OEM_LOCK_VAR		L"OEMLock"
#define KEYSTORE_VAR		L"KeyStore"
#define CRASH_EVENT_MENU_VAR	L"CrashEventMenu"
#define WDT_COUNTER_VAR		L"WatchdogCounter"
#define WDT_COUNTER_MAX_VAR	L"WatchdogCounterMax"
#define WDT_TIME_REF_VAR	L"WatchdogTimeReference"
#define DISABLE_WDT_VAR		L"DisableWatchdog"
#define UPDATE_OEMVARS		L"UpdateOemVars"
#define UI_DISPLAY_SPLASH_VAR	L"UIDisplaySplash"
#ifdef BOOTLOADER_POLICY
#define OAK_VARNAME		L"OAK"
#define BPM_VARNAME		L"BPM"

#define CLASS_A_DEVICE		1U
#define DEFAULT_BLPOLICY	0U
#endif

#define OEM_LOCK_UNLOCKED	(1 << 0)
#define OEM_LOCK_VERIFIED	(1 << 1)

#define ANDROID_PROP_VALUE_MAX	92

/* Default maximum number of watchdog resets in a row before the crash
 * event menu is displayed. */
#define WATCHDOG_COUNTER_MAX 2

const EFI_GUID fastboot_guid = { 0x1ac80a82, 0x4f0c, 0x456b,
	{0x9a, 0x99, 0xde, 0xbe, 0xb4, 0x31, 0xfc, 0xc1} };
/* Gummiboot's GUID, we use some of the same variables */
const EFI_GUID loader_guid = { 0x4a67b082, 0x0a4c, 0x41cf,
	{0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} };

/* GUIDs for various interesting Android partitions */
const CHAR16 *BOOT_LABEL = L"boot";
const CHAR16 *RECOVERY_LABEL = L"recovery";
const CHAR16 *MISC_LABEL = L"misc";

#ifdef BOOTLOADER_POLICY
const CHAR16 *FASTBOOT_SECURED_VARS[] = { OAK_VARNAME, BPM_VARNAME };
const UINTN FASTBOOT_SECURED_VARS_SIZE = ARRAY_SIZE(FASTBOOT_SECURED_VARS);
#endif

static BOOLEAN provisioning_mode = FALSE;
static enum device_state current_state = UNKNOWN_STATE;

static struct state_display {
	char *string;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color;
} STATE_DISPLAY[] = {
	{ "unknown", &COLOR_RED },
	{ "locked", &COLOR_WHITE },
	{ "verified", &COLOR_WHITE },
	{ "unlocked", &COLOR_RED }
};

static CHAR8 current_off_mode_charge[2];
static CHAR8 current_crash_event_menu[2];
static CHAR8 disable_wdt[2];
static CHAR8 current_update_oemvars[2];
static CHAR8 ui_display_splash[2];

CHAR16 *boot_state_to_string(UINT8 boot_state)
{
	switch (boot_state) {
	case BOOT_STATE_GREEN:
		return L"green";
	case BOOT_STATE_YELLOW:
		return L"yellow";
	case BOOT_STATE_ORANGE:
		return L"orange";
	case BOOT_STATE_RED:
		return L"red";
	default:
		return L"unknown";
	}
}

BOOLEAN get_current_boolean_var(const EFI_GUID *guid, CHAR16 *varname, CHAR8 cache[2],const BOOLEAN default_value)
{
	UINTN size;
	CHAR8 *data;

	if (cache[0] == '\0') {
		if (EFI_ERROR(get_efi_variable(guid, varname,
					       &size, (VOID **)&data, NULL)))
			return default_value;

		if (size != 2
		    || (strcmp(data, (CHAR8 *)"0") && strcmp(data, (CHAR8 *)"1"))) {
			FreePool(data);
			return default_value;
		}

		memcpy(cache, data, 2);
		FreePool(data);
	}

	return !strcmp(cache, (CHAR8 *)"1");
}

EFI_STATUS set_boolean_var(const EFI_GUID *guid, CHAR16 *varname, CHAR8 cache[2], BOOLEAN enabled)
{
	CHAR8 *val = (CHAR8 *)(enabled ? "1" : "0");
	EFI_STATUS ret = set_efi_variable(guid, varname,
					  2, val, TRUE, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set %s variable", varname);
		return ret;
	}

	memcpy(cache, val, 2);
	return EFI_SUCCESS;
}

BOOLEAN get_current_off_mode_charge(void)
{
	return get_current_boolean_var(&fastboot_guid, OFF_MODE_CHARGE_VAR, current_off_mode_charge, TRUE);
}

EFI_STATUS set_off_mode_charge(BOOLEAN enabled)
{
	return set_boolean_var(&fastboot_guid, OFF_MODE_CHARGE_VAR, current_off_mode_charge, enabled);
}

BOOLEAN get_current_crash_event_menu(void)
{
	return get_current_boolean_var(&fastboot_guid, CRASH_EVENT_MENU_VAR, current_crash_event_menu, TRUE);
}

EFI_STATUS set_crash_event_menu(BOOLEAN enabled)
{
	return set_boolean_var(&fastboot_guid, CRASH_EVENT_MENU_VAR, current_crash_event_menu, enabled);
}

BOOLEAN get_display_splash(void) {
	return get_current_boolean_var(&loader_guid, UI_DISPLAY_SPLASH_VAR, ui_display_splash, TRUE);
}

BOOLEAN get_oemvars_update(void)
{
	return get_current_boolean_var(&fastboot_guid, UPDATE_OEMVARS, current_update_oemvars, TRUE);
}

EFI_STATUS set_oemvars_update(BOOLEAN enabled)
{
	return set_boolean_var(&fastboot_guid, UPDATE_OEMVARS, current_update_oemvars, enabled);
}

enum device_state get_current_state()
{
	UINT8 *stored_state;
	UINTN dsize;
	EFI_STATUS ret;
	UINT32 flags;

	if (current_state == UNKNOWN_STATE) {
		ret = get_efi_variable((EFI_GUID *)&fastboot_guid, OEM_LOCK_VAR,
				       &dsize, (void **)&stored_state, &flags);
		/* If the variable does not exist, assume unlocked. */
		if (ret == EFI_NOT_FOUND) {
			provisioning_mode = TRUE;
			current_state = UNLOCKED;
			debug(L"OEMLock not set, device is in provisioning mode");
			goto exit;
		}

		/* If we can't read the state, be safe and assume locked. */
		if (EFI_ERROR(ret) || !dsize) {
			current_state = LOCKED;
			error(L"Couldn't read %s, assuming locked", OEM_LOCK_VAR);
			goto exit;
#ifndef USERFASTBOOT
		} else if (flags & EFI_VARIABLE_RUNTIME_ACCESS) {
			current_state = LOCKED;
			error(L"%s has RUNTIME_ACCESS flag, assuming locked", OEM_LOCK_VAR);
#endif
		} else {
			if (stored_state[0] & OEM_LOCK_UNLOCKED)
				current_state = UNLOCKED;
			else if (stored_state[0] & OEM_LOCK_VERIFIED)
				current_state = VERIFIED;
			else
				current_state = LOCKED;

			debug(L"device state %d", current_state);
		}
		FreePool(stored_state);
	}

exit:
	return current_state;
}

EFI_STATUS set_current_state(enum device_state state)
{
	UINT8 stored_state;

	switch (state) {
	case LOCKED:
		stored_state = 0;
		break;
	case VERIFIED:
		stored_state = OEM_LOCK_VERIFIED;
		break;
	case UNLOCKED:
		stored_state = OEM_LOCK_UNLOCKED;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}

	EFI_STATUS ret = set_efi_variable(&fastboot_guid, OEM_LOCK_VAR,
					  sizeof(stored_state), &stored_state,
					  TRUE, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set %s variable", OEM_LOCK_VAR);
		return ret;
	}

	debug(L"device state is now %d", state);
	current_state = state;
	return EFI_SUCCESS;
}

#ifndef USER
EFI_STATUS reprovision_state_vars(VOID)
{
	return del_efi_variable(&fastboot_guid, OEM_LOCK_VAR);
}
#endif

EFI_STATUS get_user_keystore(VOID **keystorep, UINTN *sizep)
{
	UINT32 flags;
	VOID *keystore;
	UINTN size;
	EFI_STATUS ret;

	ret = get_efi_variable(&fastboot_guid, KEYSTORE_VAR,
			       &size, &keystore, &flags);

	if (EFI_ERROR(ret) || size == 0) {
		debug(L"user keystore not set: %r", ret);
		return EFI_NOT_FOUND;
	}

#ifndef USERFASTBOOT
	if (flags & EFI_VARIABLE_RUNTIME_ACCESS) {
		debug(L"user keystore has bad attributes");
		FreePool(keystore);
		return EFI_NOT_FOUND;
	}
#endif
	*sizep = size;
	*keystorep = keystore;
	return EFI_SUCCESS;
}

EFI_STATUS set_user_keystore(VOID *data, UINTN size)
{
	if (size) {
		struct keystore *ks = get_keystore(data, size);

		if (!ks) {
			error(L"keystore data is invalid");
			return EFI_INVALID_PARAMETER;
		}

		free_keystore(ks);
	}

	return set_efi_variable(&fastboot_guid, KEYSTORE_VAR,
			       size, data, TRUE, FALSE);
}

char *get_current_state_string()
{
	return STATE_DISPLAY[get_current_state() + 1].string;
}

EFI_GRAPHICS_OUTPUT_BLT_PIXEL *get_current_state_color()
{
	return STATE_DISPLAY[get_current_state() + 1].color;
}

BOOLEAN device_is_unlocked()
{
	return get_current_state() == UNLOCKED;
}

BOOLEAN device_is_locked()
{
	return get_current_state() == LOCKED;
}

BOOLEAN device_is_verified()
{
	return get_current_state() == VERIFIED;
}

BOOLEAN device_is_provisioning(void)
{
	/* Force OEM_LOCK_VAR check if we haven't already */
	get_current_state();

	return provisioning_mode;
}

EFI_STATUS get_watchdog_status(UINT8 *counter, EFI_TIME *time)
{
	EFI_STATUS ret;
	EFI_TIME *tmp;
	UINTN size;
	UINT32 flags;

	ret = get_efi_variable_byte(&fastboot_guid, WDT_COUNTER_VAR,
				    counter);
	if (ret == EFI_NOT_FOUND) {
		*counter = 0;
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(ret))
		return ret;

	ret = get_efi_variable(&fastboot_guid, WDT_TIME_REF_VAR, &size,
			       (VOID **)&tmp, &flags);
	if (EFI_ERROR(ret))
		return ret;

	if (size != sizeof(*time))
		return EFI_COMPROMISED_DATA;

	memcpy(time, tmp, size);

	return EFI_SUCCESS;
}

EFI_STATUS reset_watchdog_status(VOID)
{
	EFI_STATUS ret;

	ret = set_watchdog_counter(0);
	if (EFI_ERROR(ret))
		return ret;

	return set_watchdog_time_reference(NULL);
}

EFI_STATUS set_watchdog_counter(UINT8 counter)
{
	if (counter == 0)
		return del_efi_variable(&fastboot_guid, WDT_COUNTER_VAR);

	return set_efi_variable(&fastboot_guid, WDT_COUNTER_VAR,
				sizeof(counter), &counter, TRUE, FALSE);
}

EFI_STATUS set_watchdog_time_reference(EFI_TIME *time)
{
	if (time == NULL)
		return del_efi_variable(&fastboot_guid, WDT_TIME_REF_VAR);

	return set_efi_variable(&fastboot_guid, WDT_TIME_REF_VAR,
				sizeof(*time), time, TRUE, FALSE);
}

UINT8 get_watchdog_counter_max(VOID)
{
#ifndef USER
	EFI_STATUS ret;
	UINT8 max;

	ret = get_efi_variable_byte(&fastboot_guid, WDT_COUNTER_MAX_VAR, &max);
	return EFI_ERROR(ret) ? WATCHDOG_COUNTER_MAX : max;
#else
	return WATCHDOG_COUNTER_MAX;
#endif
}

EFI_STATUS set_watchdog_counter_max(UINT8 max)
{
	return set_efi_variable(&fastboot_guid, WDT_COUNTER_MAX_VAR,
				sizeof(max), &max, TRUE, FALSE);
}

BOOLEAN get_disable_watchdog()
{
	return get_current_boolean_var(&loader_guid, DISABLE_WDT_VAR, disable_wdt, FALSE);
}

static void CDD_clean_string(char *buf)
{
	char *c;
	int len;

	/* insure the string conforms with CDD v4.4 section 3.2.2
	 * which requires matching the regexp "^[a-zA-Z0-9.,_-]+$",
	 * but disallow '.' which Google has confirmed should not be
	 * allowed in at least the device build fingerprint prefix
	 * and thus by paranoia we fall back to removing it everywhere */

	c = buf;
	while (*c) {
		if ( (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
		     (*c >= '0' && *c <='9') || (*c == ',') || (*c == '_') ||
		     (*c == '-')) {
			/* Google prefers lower case */
			*c = tolower(*c);
			/* valid character */
		} else {
			*c = '_';
		}

		c++;
	}

	len = strlena((CHAR8 *)buf);
	while (len > 0 && (buf[len - 1] == '_' || buf[len - 1] == '.')) {
		buf[len - 1] = 0;
		len = strlena((CHAR8 *)buf);
	}
}

#define SMBIOS_TO_BUFFER(buffer, type, field) do { \
	if (!buffer[0]) { \
		UINTN bufsz = sizeof(buffer); \
		char *dmidata = SMBIOS_GET_STRING(type, field); \
		if (dmidata && dmidata != SMBIOS_UNDEFINED) { \
			strncpy((CHAR8 *)buffer, (CHAR8 *)dmidata, bufsz); \
			buffer[bufsz - 1] = '\0'; \
		} \
	} \
} while(0)

char *get_property_bootloader(void)
{
	static char loader[ANDROID_PROP_VALUE_MAX];

	if (!loader[0]) {
		char buf[ANDROID_PROP_VALUE_MAX];

		buf[0] = 0;
		SMBIOS_TO_BUFFER(buf, TYPE_BIOS, BiosVersion);
		snprintf((CHAR8 *)loader, ANDROID_PROP_VALUE_MAX,
			 (CHAR8 *)"%a_%a", buf,
			 KERNELFLINGER_VERSION_8);
		CDD_clean_string(loader);
	}

	return loader;
}

#ifdef HAL_AUTODETECT
/* Remove any trailing "_inc*", "_corp*", "_gmbh*".
 * Force set some known-to-misbehave brands names to a good form */
static void chop_brand_tail(char *brand)
{
	UINTN i;

	static char *BRANDS[] = {"intel", "asus"};
	static char *SUFFIXES[] = {"_inc", "_corp", "_gmbh"};

	if (brand[0] == 0)
		return;

	/* If the brand begins with a particular string, chop off
	 * anything after it */
	for (i = 0; i < ARRAY_SIZE(BRANDS); i++) {
		char *b = BRANDS[i];
		int len = strlen((CHAR8*)b);

		if (strncasecmp(brand, b, len) == 0) {
			strcpy((CHAR8*)brand, (CHAR8*)b);
			return;
		}
	}

	/* If a particular suffix appears, get rid of it */
	for (i = 0; i < ARRAY_SIZE(SUFFIXES); i++) {
		char *c = strcasestr(brand, SUFFIXES[i]);
		if (c) {
			*c = 0;
			return;
		}
	}
}

char *get_property_name(void)
{
	static char name[ANDROID_PROP_VALUE_MAX];

	if (!name[0]) {
		SMBIOS_TO_BUFFER(name, TYPE_PRODUCT, ProductName);
		SMBIOS_TO_BUFFER(name, TYPE_BOARD, ProductName);
		CDD_clean_string(name);
		debug(L"Detected product name '%a'", name);
	}

	return name;
}

/* product_vendor observed to be blank on some devices
 * bios_vendor will be different than what we want here (DO NOT USE IT)
 * board_vendor observed to be reasonable on sample of devices */
char *get_property_brand(void)
{
	static char brand[ANDROID_PROP_VALUE_MAX];

	if (!brand[0]) {
		SMBIOS_TO_BUFFER(brand, TYPE_BOARD, Manufacturer);
		SMBIOS_TO_BUFFER(brand, TYPE_PRODUCT, Manufacturer);
		CDD_clean_string(brand);
		chop_brand_tail(brand);
		debug(L"Detected product brand '%a'", brand);
	}

	return brand;
}

char *get_property_model(void)
{
	/* FIXME This is supposed to be read from some non-standard
	 * "board_name1" field, but without a specification we
	 * can't do anything. Menwhile just return the device */
	return get_property_device();
}

char *get_property_device(void)
{
	static char device[ANDROID_PROP_VALUE_MAX];
	if (!device[0]) {
		char board_name[ANDROID_PROP_VALUE_MAX];
		char board_version[ANDROID_PROP_VALUE_MAX];

		board_name[0] = 0;
		board_version[0] = 0;

		SMBIOS_TO_BUFFER(board_name, TYPE_BOARD, ProductName);
		SMBIOS_TO_BUFFER(board_version, TYPE_BOARD, Version);

		if (board_version[0]) {
			snprintf((CHAR8 *)device, ANDROID_PROP_VALUE_MAX,
				 (CHAR8 *)"%a_%a", board_name, board_version);
		} else {
			snprintf((CHAR8 *)device, ANDROID_PROP_VALUE_MAX,
				 (CHAR8*)"%a", board_name);
		}
		CDD_clean_string(device);
		debug(L"Detected product device '%a'", device);
	}

	return device;
}

char *get_device_id(void)
{
	static char deviceid[ANDROID_PROP_VALUE_MAX];
	if (!deviceid[0]) {
		snprintf((CHAR8 *)deviceid, sizeof(deviceid),
			 (CHAR8 *)"%a/%a/%a", get_property_brand(),
			 get_property_name(), get_property_device());
	}
	return deviceid;
}
#else
char *get_device_id(void)
{
	return "DEFAULT";
}
#endif

/* Per Android CDD, the value must be 7-bit ASCII and match the regex
 * ^[a-zA-Z0-9](6,20)$  */
char *get_serial_number(void)
{
	static char serialno[SERIALNO_MAX_SIZE + 1];
	char *pos;
	unsigned int zeroes = 0;
	UINTN len;

	if (serialno[0] != '\0')
		return serialno;

	SMBIOS_TO_BUFFER(serialno, TYPE_PRODUCT, SerialNumber);
	SMBIOS_TO_BUFFER(serialno, TYPE_CHASSIS, SerialNumber);
	SMBIOS_TO_BUFFER(serialno, TYPE_BOARD, SerialNumber);
	SMBIOS_TO_BUFFER(serialno, TYPE_CHASSIS, AssetTag);

	if (!serialno[0]) {
		error(L"couldn't read serial number from SMBIOS");
		goto bad;
	}

	/* basic IQ test for BIOS s/n:
	 * Check for stuff like "System Serial Number",
	 * "To be filled by O.E.M,, common non-random number.
	 * Not intended to be exhaustive */
	if ((strcasestr(serialno, "serial") != NULL) ||
	    (strcasestr(serialno, "filled") != NULL) ||
	    (strcasestr(serialno, "12345678") != NULL)) {
		error(L"SMBIOS has a bad serial number");
		goto bad;
	}

	for (pos = serialno; *pos; pos++) {
		/* Replace foreign characters with zeroes */
		if (!((*pos >= '0' && *pos <= '9') ||
		      (*pos >= 'a' && *pos <= 'z') ||
		      (*pos >= 'A' && *pos <= 'Z')))
			*pos = '0';
		if (*pos == '0')
			zeroes++;
	}

	len = strlena((CHAR8 *)serialno);
	/* If it's too short or is all zeroes reject it */
	if (len < SERIALNO_MIN_SIZE) {
		error(L"SMBIOS serial number too short");
		goto bad;
	}

	if (len == zeroes) {
		error(L"SMBIOS serial number is all zeroes");
		goto bad;
	}

	return serialno;
bad:
	strncpy((CHAR8 *)serialno, (CHAR8 *)"00badbios00badbios00",
		SERIALNO_MAX_SIZE);
	return serialno;
}

#ifdef BOOTLOADER_POLICY
BOOLEAN blpolicy_is_flashed(VOID)
{
	EFI_STATUS ret;
	UINTN size, i;
	UINT32 flags;
	VOID *data;

	for (i = 0; i < FASTBOOT_SECURED_VARS_SIZE; i++) {
		ret = get_efi_variable(&fastboot_guid, (CHAR16 *)FASTBOOT_SECURED_VARS[i],
				       &size, (VOID **)&data, &flags);
		if (EFI_ERROR(ret))
			return FALSE;

		FreePool(data);
		if (!(flags & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS))
			return FALSE;
	}

	return TRUE;
}

BOOLEAN device_is_class_A(VOID)
{
	EFI_STATUS ret;
	UINTN size;
	UINT32 flags;
	UINT64 *bpm_data;
	UINT64 bpm = DEFAULT_BLPOLICY;

	ret = get_efi_variable(&fastboot_guid, BPM_VARNAME,
			       &size, (VOID **)&bpm_data, &flags);
	if (EFI_ERROR(ret))
		goto out;

	if (size != sizeof(bpm) ||
	    !(flags & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
		FreePool(bpm_data);
		goto out;
	}

	bpm = *bpm_data;
	FreePool(bpm_data);

out:
	return (bpm & CLASS_A_DEVICE) != 0;
}

EFI_STATUS get_oak_hash(unsigned char **data_p, UINTN *size)
{
	EFI_STATUS ret;
	UINT32 flags;
	VOID *data;

	ret = get_efi_variable(&fastboot_guid, OAK_VARNAME,
			       size, (VOID **)&data, &flags);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read OAK EFI variable");
		return ret;
	}

	if (!(flags & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
		FreePool(data);
		return EFI_SECURITY_VIOLATION;
	}

	*data_p = data;

	return EFI_SUCCESS;
}
#endif
