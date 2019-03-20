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

#include "signature.h"
#include "vars.h"
#include "ui.h"
#include "lib.h"
#include "smbios.h"
#include "version.h"
#include "life_cycle.h"
#include "storage.h"
#ifdef RPMB_STORAGE
#include "rpmb_storage.h"
#endif

#define OFF_MODE_CHARGE		L"off-mode-charge"
#define OEM_LOCK		L"OEMLock"
#define CRASH_EVENT_MENU	L"CrashEventMenu"
#define WDT_COUNTER		L"WatchdogCounter"
#define WDT_COUNTER_MAX		L"WatchdogCounterMax"
#define WDT_TIME_REF		L"WatchdogTimeReference"
#define DISABLE_WDT		L"DisableWatchdog"
#define UPDATE_OEMVARS		L"UpdateOemVars"
#define UI_DISPLAY_SPLASH	L"UIDisplaySplash"
#define REBOOT_REASON		L"LoaderEntryRebootReason"
#ifndef USER
#define SLOT_FALLBACK		L"SlotFallback"
#endif
#ifdef BOOTLOADER_POLICY_EFI_VAR
#define OVERRIDE_AUTHORIZATION_KEY	L"OAK"
#define BOOTLOADER_POLICY_MASK		L"BPM"
#endif
#define ROLLBACK_INDEX_FMT		L"RollbackIndex_%04x"
#define LOADED_SLOT		L"LoadedSlot"

#ifdef BOOTLOADER_POLICY
typedef union {
	struct {
		unsigned class_A : 1;
		unsigned min_boot_state : 2;
	};
	UINT64 raw;
} bpm_t;

#define DEFAULT_BLPOLICY	0U
#endif

#define OEM_LOCK_UNLOCKED	(1 << 0)

#define ANDROID_PROP_VALUE_MAX	92
#define REBOOT_REASON_MAX 	64

/* Default maximum number of watchdog resets in a row before the crash
 * event menu is displayed. */
#define WATCHDOG_COUNTER_MAX 2

const EFI_GUID fastboot_guid = { 0x1ac80a82, 0x4f0c, 0x456b,
	{0x9a, 0x99, 0xde, 0xbe, 0xb4, 0x31, 0xfc, 0xc1} };
/* Gummiboot's GUID, we use some of the same variables */
const EFI_GUID loader_guid = { 0x4a67b082, 0x0a4c, 0x41cf,
	{0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} };

#ifdef BOOTLOADER_POLICY_EFI_VAR
const CHAR16 *FASTBOOT_SECURED_VARS[] = { OVERRIDE_AUTHORIZATION_KEY, BOOTLOADER_POLICY_MASK };
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
	{ "unlocked", &COLOR_RED }
};

typedef struct bool_value {
	UINT8 is_cached : 1;
	UINT8 value : 1;
} __attribute__((__packed__)) bool_value_t;

static bool_value_t off_mode_charge;
static bool_value_t crash_event_menu;
static bool_value_t disable_wdt;
static bool_value_t update_oemvars;
static bool_value_t ui_display_splash;
#ifndef USER
static bool_value_t slot_fallback;
#endif

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

BOOLEAN get_current_boolean_var(const EFI_GUID *guid, CHAR16 *varname,
				bool_value_t *cache, const BOOLEAN default_value)
{
	EFI_STATUS ret;
	UINTN size;
	CHAR8 *data = NULL;

	if (cache->is_cached)
		return cache->value;

	cache->is_cached = 1;
	cache->value = default_value;

	ret = get_efi_variable(guid, varname, &size, (VOID **)&data, NULL);
	if (EFI_ERROR(ret))
		goto exit;

	if (size != 2 || data[1] != '\0' || (data[0] != '1' && data[0] != '0'))
		goto exit;

	cache->value = data[0] == '1' ? 1 : 0;

exit:
	if (data)
		FreePool(data);
	return cache->value;
}

EFI_STATUS set_boolean_var(const EFI_GUID *guid, CHAR16 *varname,
			   bool_value_t *cache, BOOLEAN enabled)
{
	CHAR8 *val = (CHAR8 *)(enabled ? "1" : "0");
	EFI_STATUS ret;

	ret = set_efi_variable(guid, varname, 2, val, TRUE, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set %s variable", varname);
		return ret;
	}

	cache->is_cached = 1;
	cache->value = enabled;

	return EFI_SUCCESS;
}

BOOLEAN get_off_mode_charge(void)
{
	return get_current_boolean_var(&fastboot_guid, OFF_MODE_CHARGE,
				       &off_mode_charge, TRUE);
}

EFI_STATUS set_off_mode_charge(BOOLEAN enabled)
{
	return set_boolean_var(&fastboot_guid, OFF_MODE_CHARGE,
			       &off_mode_charge, enabled);
}

BOOLEAN get_crash_event_menu(void)
{
	return get_current_boolean_var(&fastboot_guid, CRASH_EVENT_MENU,
				       &crash_event_menu, TRUE);
}

EFI_STATUS set_crash_event_menu(BOOLEAN enabled)
{
	return set_boolean_var(&fastboot_guid, CRASH_EVENT_MENU,
			       &crash_event_menu, enabled);
}

BOOLEAN get_display_splash(void) {
	return get_current_boolean_var(&loader_guid, UI_DISPLAY_SPLASH,
				       &ui_display_splash, TRUE);
}

BOOLEAN get_oemvars_update(void)
{
	return get_current_boolean_var(&fastboot_guid, UPDATE_OEMVARS,
				       &update_oemvars, TRUE);
}

EFI_STATUS set_oemvars_update(BOOLEAN enabled)
{
	return set_boolean_var(&fastboot_guid, UPDATE_OEMVARS,
			       &update_oemvars, enabled);
}

BOOLEAN get_slot_fallback(void)
{
#ifndef USER
	return get_current_boolean_var(&fastboot_guid, SLOT_FALLBACK,
				       &slot_fallback, TRUE);
#else
	return TRUE;
#endif
}

EFI_STATUS set_slot_fallback(BOOLEAN enabled)
{
#ifndef USER
	return set_boolean_var(&fastboot_guid, SLOT_FALLBACK,
			       &slot_fallback, enabled);
#else
	(void)enabled;	/* Unused parameter.  */
	return EFI_UNSUPPORTED;
#endif
}

static void set_provisioning_mode(BOOLEAN provisioning)
{
	provisioning_mode = provisioning;
	current_state = provisioning ? UNLOCKED : LOCKED;
}

enum device_state get_current_state()
{
	UINT8 *stored_state;
	UINTN dsize;
	EFI_STATUS ret;
	UINT32 flags;
	BOOLEAN enduser;
#ifdef SECURE_STORAGE_RPMB
	UINT8 val;
#endif

	if (current_state == UNKNOWN_STATE) {
#ifdef SECURE_STORAGE_RPMB
		ret = read_rpmb_device_state(&val);
		stored_state = &val;
		dsize = 1;
		flags = EFI_VARIABLE_NON_VOLATILE;
#else
		ret = get_efi_variable((EFI_GUID *)&fastboot_guid, OEM_LOCK,
				       &dsize, (void **)&stored_state, &flags);
#endif
		if ((ret == EFI_NOT_FOUND) && !is_boot_device_virtual()) {
			set_provisioning_mode(FALSE);

			ret = life_cycle_is_enduser(&enduser);
			if (EFI_ERROR(ret)) {
				if (ret == EFI_NOT_FOUND) {
					debug(L"OEMLock not set, device is in provisioning mode");
					set_provisioning_mode(TRUE);
				}
				goto exit;
			}

			if (!enduser) {
				debug(L"Life Cycle state is not ENDUSER, allowing provisioning mode");
				set_provisioning_mode(TRUE);
				goto exit;
			}

#ifndef USER
			debug(L"Life Cycle state is ENDUSER");
			debug(L"Not a USER build, enforcing provisioning mode");
			set_provisioning_mode(TRUE);
#endif
			goto exit;
		}

		/* If we can't read the state, be safe and assume locked. */
		if (EFI_ERROR(ret) || !dsize) {
			current_state = LOCKED;
			error(L"Couldn't read %s, assuming locked", OEM_LOCK);
			goto exit;
		} else if (flags & EFI_VARIABLE_RUNTIME_ACCESS) {
			current_state = LOCKED;
			error(L"%s has RUNTIME_ACCESS flag, assuming locked", OEM_LOCK);
		} else {
			if (stored_state[0] & OEM_LOCK_UNLOCKED)
				current_state = UNLOCKED;
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
	EFI_STATUS ret;

	switch (state) {
	case LOCKED:
		stored_state = 0;
		break;
	case UNLOCKED:
		stored_state = OEM_LOCK_UNLOCKED;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}

#ifdef SECURE_STORAGE_RPMB
	ret = write_rpmb_device_state(stored_state);
#else
	ret = set_efi_variable(&fastboot_guid, OEM_LOCK,
					  sizeof(stored_state), &stored_state,
					  TRUE, FALSE);
#endif
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set %s variable", OEM_LOCK);
		return ret;
	}

	debug(L"device state is now %d", state);
	current_state = state;
	return EFI_SUCCESS;
}

EFI_STATUS refresh_current_state(void)
{
	current_state = UNKNOWN_STATE;
	get_current_state();

	return EFI_SUCCESS;
}

#ifndef USER
EFI_STATUS reprovision_state_vars(VOID)
{
	return del_efi_variable(&fastboot_guid, OEM_LOCK);
}

static struct efivar_black_list {
	const CHAR16 *name;
	const EFI_GUID *guid;
} EFIVAR_BLACK_LIST[] = {
	{ .name = OEM_LOCK, &fastboot_guid },
	/* We cannot delete the LOG_VAR EFI variable because
	   Kernelflinger continously saves all the error messages in
	   it. Deleting it could lead to a infinite loop. */
	{ .name = LOG_VAR, &loader_guid }
};

EFI_STATUS erase_efivars(VOID)
{
	EFI_STATUS ret;
	UINTN bufsize, namesize;
	CHAR16 *name;
	EFI_GUID guid;
	UINTN i;

	bufsize = 64;		/* Initial size large enough to handle
				   usual variable names length and
				   avoid the ReallocatePool call as
				   much as possible.  */
	name = AllocateZeroPool(bufsize);
	if (!name) {
		error(L"Failed to allocate variable name buffer");
		return EFI_OUT_OF_RESOURCES;
	}

	for (;;) {
		namesize = bufsize;
		ret = uefi_call_wrapper(RT->GetNextVariableName, 3, &namesize,
					name, &guid);
		if (ret == EFI_NOT_FOUND) {
			ret = EFI_SUCCESS;
			goto exit;
		}
		if (ret == EFI_BUFFER_TOO_SMALL) {
			name = ReallocatePool(name, bufsize, namesize);
			if (!name) {
				error(L"Failed to re-allocate variable name buffer");
				return EFI_OUT_OF_RESOURCES;
			}
			bufsize = namesize;
			continue;
		}
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"GetNextVariableName failed");
			goto exit;
		}

		if (memcmp(&loader_guid, &guid, sizeof(guid)) &&
		    memcmp(&fastboot_guid, &guid, sizeof(guid)))
			continue;

#ifdef BOOTLOADER_POLICY_EFI_VAR
		if (!memcmp(&guid, &fastboot_guid, sizeof(guid)))
			for (i = 0; i < FASTBOOT_SECURED_VARS_SIZE; i++)
				if (!StrCmp(FASTBOOT_SECURED_VARS[i], name))
					goto skip;
#endif	/* BOOTLOADER_POLICY_EFI_VAR */

		for (i = 0; i < ARRAY_SIZE(EFIVAR_BLACK_LIST); i++) {
			if (!StrCmp(EFIVAR_BLACK_LIST[i].name, name) &&
			    !memcmp(EFIVAR_BLACK_LIST[i].guid, &guid, sizeof(guid)))
				goto skip;
		}

		ret = del_efi_variable(&guid, name);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to delete %s:%g EFI variable", name, &guid);
		else {
			debug(L"%s:%g EFI variable has been deleted", name, &guid);
			/* If we have deleted a variable, we are
			   loosing the "previous variable reference"
			   and we have to start over. */
			name[0] = '\0';
		}
skip:
		continue;
	}

exit:
	FreePool(name);
	return ret;
}
#endif

const char *get_current_state_string()
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

BOOLEAN device_is_provisioning(void)
{
	/* Force OEM_LOCK check if we haven't already */
	get_current_state();

	return provisioning_mode;
}

EFI_STATUS get_watchdog_status(UINT8 *counter, EFI_TIME *time)
{
	EFI_STATUS ret;
	EFI_TIME *tmp;
	UINTN size;
	UINT32 flags;

	ret = get_efi_variable_byte(&fastboot_guid, WDT_COUNTER,
				    counter);
	if (ret == EFI_NOT_FOUND) {
		*counter = 0;
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(ret))
		return ret;

	ret = get_efi_variable(&fastboot_guid, WDT_TIME_REF, &size,
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
		return del_efi_variable(&fastboot_guid, WDT_COUNTER);

	return set_efi_variable(&fastboot_guid, WDT_COUNTER,
				sizeof(counter), &counter, TRUE, FALSE);
}

EFI_STATUS set_watchdog_time_reference(EFI_TIME *time)
{
	if (time == NULL)
		return del_efi_variable(&fastboot_guid, WDT_TIME_REF);

	return set_efi_variable(&fastboot_guid, WDT_TIME_REF,
				sizeof(*time), time, TRUE, FALSE);
}

UINT8 get_watchdog_counter_max(VOID)
{
#ifndef USER
	EFI_STATUS ret;
	UINT8 max;

	ret = get_efi_variable_byte(&fastboot_guid, WDT_COUNTER_MAX, &max);
	return EFI_ERROR(ret) ? WATCHDOG_COUNTER_MAX : max;
#else
	return WATCHDOG_COUNTER_MAX;
#endif
}

EFI_STATUS set_watchdog_counter_max(UINT8 max)
{
	return set_efi_variable(&fastboot_guid, WDT_COUNTER_MAX,
				sizeof(max), &max, TRUE, FALSE);
}

BOOLEAN get_disable_watchdog()
{
	return get_current_boolean_var(&loader_guid, DISABLE_WDT,
				       &disable_wdt, FALSE);
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
		efi_snprintf((CHAR8 *)loader, ANDROID_PROP_VALUE_MAX,
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
			efi_snprintf((CHAR8 *)device, ANDROID_PROP_VALUE_MAX,
				     (CHAR8 *)"%a_%a", board_name, board_version);
		} else {
			efi_snprintf((CHAR8 *)device, ANDROID_PROP_VALUE_MAX,
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
		efi_snprintf((CHAR8 *)deviceid, sizeof(deviceid),
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

char *get_serialno_var()
{
	CHAR8 *data;
	EFI_STATUS ret;
	UINTN size;

	ret = get_efi_variable(&loader_guid, SERIAL_NUM_VAR, &size, (VOID **)&data,NULL);
	if (EFI_ERROR(ret) || !data || !size)
		return NULL;
	if (data[size - 1] != '\0') {
		FreePool(data);
		return NULL;
	}
	return (char *)data;
}

/* Per Android CDD, the value must be 7-bit ASCII and match the regex
 * ^[a-zA-Z0-9](6,20)$  */
char *get_serial_number(void)
{
	static char bios_serialno[SERIALNO_MAX_SIZE + 1];
	static char serialno[SERIALNO_MAX_SIZE + 1];
	char *pos;
	unsigned int zeroes = 0;
	UINTN len;

	if (serialno[0] != '\0')
		return serialno;

	SMBIOS_TO_BUFFER(bios_serialno, TYPE_PRODUCT, SerialNumber);
	SMBIOS_TO_BUFFER(bios_serialno, TYPE_CHASSIS, SerialNumber);
	SMBIOS_TO_BUFFER(bios_serialno, TYPE_BOARD, SerialNumber);
	SMBIOS_TO_BUFFER(bios_serialno, TYPE_CHASSIS, AssetTag);

	if (!bios_serialno[0]) {
		error(L"couldn't read serial number from SMBIOS");
		goto bad;
	}

	/* basic IQ test for BIOS s/n:
	 * Check for stuff like "System Serial Number",
	 * "To be filled by O.E.M,, common non-random number.
	 * Not intended to be exhaustive */
	if ((strcasestr(bios_serialno, "serial") != NULL) ||
	    (strcasestr(bios_serialno, "filled") != NULL) ||
	    (strcasestr(bios_serialno, "12345678") != NULL)) {
		error(L"SMBIOS has a bad serial number");
		goto bad;
	}

#ifdef BUILD_ANDROID_THINGS
	efi_snprintf((CHAR8*)serialno, SERIALNO_MAX_SIZE, (CHAR8*) "%a%a", TARGET_BOOTLOADER_BOARD_NAME, bios_serialno);
#else
	efi_snprintf((CHAR8*)serialno, SERIALNO_MAX_SIZE, (CHAR8*) "%a", bios_serialno);
#endif

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
#ifdef BUILD_ANDROID_THINGS
	pos = get_serialno_var();
	if (pos == NULL) {
		error(L"SERIAL number is NULL\n");
		strncpy((CHAR8 *)serialno, (CHAR8 *)"00badbios00badbios00", SERIALNO_MAX_SIZE);
	} else {
		error(L"Valid serial number read from EFI vars\n");
		strncpy((CHAR8 *)serialno, (CHAR8 *)pos, SERIALNO_MAX_SIZE);
		FreePool(pos);
	}
#else
	strncpy((CHAR8 *)serialno, (CHAR8 *)"00badbios00badbios00", SERIALNO_MAX_SIZE);
#endif
	return serialno;
}

CHAR16 *get_reboot_reason()
{
	static CHAR16 reboot_reason[REBOOT_REASON_MAX];
	CHAR16 *rr;

	if (reboot_reason[0])
		return reboot_reason;

	rr = get_efi_variable_str(&loader_guid, REBOOT_REASON);
	if (!rr)
		return NULL;

	if (StrLen(rr) >= REBOOT_REASON_MAX)
		error(L"Reboot reason string is too long, truncating");

	StrNCpy(reboot_reason, rr, REBOOT_REASON_MAX);
	FreePool(rr);

	return reboot_reason;
}

EFI_STATUS set_reboot_reason(CHAR16 *reboot_reason)
{
	EFI_STATUS ret;

	if (reboot_reason[0] == 0)
		return EFI_INVALID_PARAMETER;

	ret = set_efi_variable_str(&loader_guid, REBOOT_REASON, FALSE, FALSE, reboot_reason);
	return ret;
}

BOOLEAN is_reboot_reason(CHAR16 *reason)
{
	CHAR16 *rr = get_reboot_reason();

	return rr && StrStr(rr, reason);
}

VOID del_reboot_reason()
{
	del_efi_variable(&loader_guid, REBOOT_REASON);
}

#ifdef BOOTLOADER_POLICY
#ifdef BOOTLOADER_POLICY_EFI_VAR
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

static bpm_t get_bpm()
{
	EFI_STATUS ret;
	UINTN size;
	UINT32 flags;
	UINT64 *bpm_data;
	bpm_t bpm = { .raw = DEFAULT_BLPOLICY };

	ret = get_efi_variable(&fastboot_guid, BOOTLOADER_POLICY_MASK,
			       &size, (VOID **)&bpm_data, &flags);
	if (EFI_ERROR(ret))
		goto out;

	if (size != sizeof(bpm) ||
	    !(flags & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
		FreePool(bpm_data);
		goto out;
	}

	bpm.raw = *bpm_data;
	FreePool(bpm_data);

out:
	return bpm;
}

EFI_STATUS get_oak_hash(unsigned char **data_p, UINTN *size)
{
	EFI_STATUS ret;
	UINT32 flags;
	VOID *data;

	ret = get_efi_variable(&fastboot_guid, OVERRIDE_AUTHORIZATION_KEY,
			       size, (VOID **)&data, &flags);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read %s EFI variable",
			   OVERRIDE_AUTHORIZATION_KEY);
		return ret;
	}

	if (!(flags & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
		FreePool(data);
		return EFI_SECURITY_VIOLATION;
	}

	*data_p = data;

	return EFI_SUCCESS;
}

#else  // BOOTLOADER_POLICY_EFI_VAR
static bpm_t get_bpm()
{
	bpm_t bpm = { .raw = BOOTLOADER_POLICY };
	return bpm;
}
#endif	/* BOOTLOADER_POLICY_EFI_VAR */

BOOLEAN device_is_class_A(VOID)
{
	return get_bpm().class_A != 0;
}

UINT8 min_boot_state_policy()
{
	switch (get_bpm().min_boot_state) {
	case 1:
		return BOOT_STATE_ORANGE;
	case 2:
		return BOOT_STATE_YELLOW;
	case 3:
		return BOOT_STATE_GREEN;
	}
	return BOOT_STATE_RED;
}
#endif	/* BOOTLOADER_POLICY */

BOOLEAN is_UEFI(VOID)
{
	static bool_value_t val;
	EFI_STATUS ret;
	EFI_GUID EFIWRAPPER_GUID =
		{ 0x59d0d866, 0x5637, 0x47a9,
		  { 0xb7, 0x50, 0x42, 0x60, 0x0a, 0x54, 0x5b, 0x63 }};
	void *unused;

	if (val.is_cached)
		return val.value;

        ret = LibLocateProtocol(&EFIWRAPPER_GUID, &unused);
	val.value = !!EFI_ERROR(ret);
	val.is_cached = 1;

	return val.value;
}

#if defined(SECURE_STORAGE_EFIVAR) && defined(USE_AVB)
EFI_STATUS read_efi_rollback_index(UINTN rollback_index_slot, uint64_t* out_rollback_index)
{
	EFI_STATUS ret;
	CHAR16 name[32];
	UINTN size;
	UINT32 flags;
	VOID *data;

	SPrint(name, sizeof(name), ROLLBACK_INDEX_FMT, rollback_index_slot);
	ret = get_efi_variable(&fastboot_guid, name,
			       &size, (VOID **)&data, &flags);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read %s EFI variable", name);
		return ret;
	} else
		debug(L"Success to read %s EFI variable: 0x%llx ", name, *(uint64_t *)data);

	if (size != sizeof(*out_rollback_index))
		return EFI_COMPROMISED_DATA;

	*out_rollback_index = *(uint64_t *)data;

	return EFI_SUCCESS;
}

EFI_STATUS write_efi_rollback_index(UINTN rollback_index_slot, uint64_t rollback_index)
{
	EFI_STATUS ret;
	CHAR16 name[32];

	SPrint(name, sizeof(name), ROLLBACK_INDEX_FMT, rollback_index_slot);
	ret = set_efi_variable(&fastboot_guid, name,
			       sizeof(rollback_index), &rollback_index, TRUE, FALSE);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to set %s EFI variable", name);
	else
		debug(L"Success to set %s EFI variable: 0x%llx ", name, rollback_index);

	return ret;
}

EFI_STATUS set_efi_loaded_slot(UINT8 slot)
{
	return set_efi_variable(&fastboot_guid, LOADED_SLOT,
				sizeof(slot), &slot, FALSE, FALSE);
}

EFI_STATUS get_efi_loaded_slot(UINT8 *slot)
{
	return get_efi_variable_byte(&fastboot_guid, LOADED_SLOT,
				slot);
}

#endif // defined(SECURE_STORAGE_EFIVAR) && defined(USE_AVB)
