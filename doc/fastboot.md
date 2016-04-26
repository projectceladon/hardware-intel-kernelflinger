Fastboot
========

This documentation presents the particularities of the Kernelflinger
Fastboot implementation.  For *fastboot* standard commands, please
refer to `fastboot --help`.

Non-standard `flash` commands
-----------------------------

### `flash gpt <filename>`

Unlocked devices only. Provisions the GPT partition scheme on the
device, accepting an `gpt.bin` file which contains a specification for
the device's GPT.

`gpt.bin` file is generated using the
[gpt_ini2bin.py](https://android.googlesource.com/platform/hardware/bsp/intel/+/de59ae73d7e3e139f1a5d31f4d107c996c377be5/soc/edison/tools/gpt_ini2bin.py)
script from a `gpt.ini` file.

Here is a `gpt.ini` file example:

```ini
[base]
partitions = bootloader bootloader2 boot recovery misc metadata system cache data persistent
device = auto

[partition.bootloader]
label = bootloader
len = 60
type = esp

[partition.bootloader2]
label = bootloader2
len = 60
type = fat

[partition.boot]
label = boot
len = 30
type = boot

[partition.recovery]
label = recovery
len = 30
type = recovery

[partition.misc]
label = misc
len = 1
type = misc

[partition.metadata]
label = metadata
len = 16
type = metadata

[partition.system]
label = system
len = 2560
type = linux

[partition.cache]
label = cache
len = 100
type = linux

[partition.data]
label = data
len = -1
type = linux

[partition.persistent]
label = persistent
len = 1
type = linux
```

### `fastboot flash bootloader <filename>`

Unlocked devices only. Kernelfinger Fastboot implementation requires
two `bootloader` partitions labelled `bootloader` and
`bootloader2`. The `flash bootloader` process is the following:

1. Flash `FILENAME` into the `bootloader2` partition.
2. Verify the content of the `bootloader2` partition:
  * `bootloader2` contains a FAT16 or FAT32 file-system
  * the usual bootloader EFI binary is present and loadable
  * and all the EFI binaries described in the `/manifest.txt` file are
    present and loadable.
3. Switch the `bootloader` and `bootloader2` entries in the GPT
   header.
4. Create the load options based on the `bootloader` partition
   `/manifest.txt` file.

Here is an example of a `/manifest.txt` file:
``` conf
Android-IA=/EFI/BOOT/bootx64.efi
Fastboot=/EFI/BOOT/bootx64.efi;-f
```

This `/manifest.txt` file makes Kernelflinger create two load options
`Android-IA` and `Fastboot`. The `Fastboot` load option makes the EFI
Boot Manager start Kernelflinger with the "-f" supplied argument,
enforcing Kernelflinger to start in Fastboot mode.

### `fastboot flash oemvars <filename>`

Unlocked devices only. OEM variables are stored as EFI variables. By
default, they are under the Loader GUID of
`4a67b082-0a4c-41cf-b6c7-440b29bb8c4f`.

This flash command accepts a text file with a set of OEM variables to
set. The syntax supports #-style end of line comments. Variable
settings are specified as `<var> <val>`. White space around the
variable name is removed, as is trailing white space at the end of the
line. The value can otherwise contain any printable character and is
stored as an 8-bit string in the EFI variable's value. Non-printable
bytes can be encoded with `%xx` URL-style notation. If `<val>` is
omitted, the variable is cleared instead.

A line of the form follows:

``` conf
GUID = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

This line changes the GUID used for subsequent lines.

Example file:

``` conf
##########################
# Maximum timeout to check for magic key at boot; fastboot GUID

MagicKeyTimeout     40

##########################
# atomisp camera variables

GUID = ecb54cd9-e5ae-4fdc-a971-e877756068f7

# ECS boards use this GPIO line to gate 2.8v camera power
gmin_V2P8GPIO 402

# OV5693 world-facing camera
INT33BE:00_CsiPort   1
INT33BE:00_CsiLanes  2
INT33BE:00_CamClk    0
INT33BE:00_CsiFmt   13
INT33BE:00_CsiBayer  2

# Aptina MT9M114 ("SOC-1040") user-facing camera
INT33F0:00_CsiPort   0
INT33F0:00_CsiLanes  1
INT33F0:00_CamClk    1
INT33F0:00_CsiFmt   13
INT33F0:00_CsiBayer  0

# Invert Audio Jack
byt_rt5640_JackInvert 1
```

Additionally, lines may be prefixed with modifier codes in brackets to
control the flags used when setting EFI variables. By default, all
values are assumed to be 8-bit NUL-terminated strings with both boot
and runtime services access. Supported modifier codes are:

* `d`: Raw data, do not NUL terminate
* `b`: Restrict to boot services access
* `a`: Time-based authenticated variable

For example:

``` conf
[db] MyBinaryVar %ab%cd%ef
```

This example sets MyBinaryVar to the hex values 0xAB 0xCD 0xEF with no
terminating NUL byte and boot services access only.

### `flash /ESP/<dest-path> <filename>`

Unlocked devices only. Copy `FILENAME` into the EFI system partition.
Any directory included in `DEST` path will also be created.

OEM commmands
-------------

### `oem setvar <var-name> [<var-value>]`

Unlocked devices only. Sets an EFI variable under the Loader GUID
`4a67b082-0a4c-41cf-b6c7-440b29bb8c4f` with the specified key, to the
value provided. The value is always stored as an 8-bit NUL-terminated
string. Omitting the value will result in the variable being set to
NUL which will erase the variable.

Some interesting values that can be set are:

* `SerialPort`: Value is appended to `console=` in the kernel command
  line for setting the device's console port.
* `AppendCmdline`, `PrependCmdline`, and `ReplaceCmdline`:

1. The content of variable `PrependCmdline` will be prepended to the
   original commandline.
2. The content of variable `AppendCmdline` will be appended to the
    original commandline.
3. The content of variable `ReplaceCmdline` will replace the whole
   original commandline.
4. The `PrependCmdline` and `AppendCmdline` will still be effective,
   using the content of `RepaceCmdline`.
5. `AppendCmdline`, `PrependCmdline`, and `ReplaceCmdline` will be
   ignored in a `user` build.

Other values are inherently device-specific. Normally this command is
only of interest to developers. Factory provisioning uses flash
oemvars instead.

### `oem garbage-disk`

Unlocked devices only. Writes out the entire disk with random data,
including the partition table. Used in device provisioning test cases
to ensure that the previous device state does not influence the
outcome of the tests applied.

### `oem reboot <target>`

Works in any device state. Reboots the device into the specified boot
TARGET.  Functionally equivalent to `adb reboot <target>`.

### `oem reprovision`

Works in any device state. This is only available in `eng` or
`userdebug` builds. It puts the device back into provisioning mode,
which allows several things:

* The device may be unlocked without enforcing Factory Reset
  Protection. The state of the persistent partition doesn't matter.
* Transitions between `{locked|unlocked}` states do not require user
  confirmation or erasing of the `userdata` partition.

Provisioning mode is also the state the device is in when it is
freshly manufactured. The device leaves provisioning mode once you run
any of the `flashing {lock|unlock}` commands and you reset the device.

### `oem rm /ESP/<filename>`

Unlocked devices only.  Erase FILENAME from the EFI system partition.

### `oem get-hashes <hash-algorithm>`

Works in any device state. This is used by OTA Secure Boot Test Cases
to verify the correctness of device provisioning and OTA
updates. Various boot images, the contents of the EFI system
partition, and the block-level /system and /vendor images (including
verity tables and metadata) are HASH-ALGORITHM hashed and reported
back to the user.

Example:

``` bash
...
& fastboot oem get-hashes
(bootloader) target: /boot
(bootloader) hash: d0448a1e91030e5c37277e4a77eabefc36fc8e6c
(bootloader) target: /recovery
(bootloader) hash: 411c61de23f6f73934b79eda4f64779706c220f4
(bootloader) target: /bootloader/EFI/BOOT/bootx64.efi
(bootloader) hash: 2773c4c039dc37b96171f6ef131f04dd8faf73e1
(bootloader) target: /bootloader/loader.efi
(bootloader) hash: 2773c4c039dc37b96171f6ef131f04dd8faf73e1
(bootloader) target: /bootloader/fastboot.img
(bootloader) hash: b0b3d122c4dca255ed2a75268ef30f6cbbc11085
(bootloader) target: /system
(bootloader) hash: d417239a25df718d73b6326e6c93a7fc1b00afb2
OKAY [134.307s]
finished. total time: 134.307s
```

This command takes an optional argument to specify which
HASH-ALGORITHM must be used.  Accepted values are "sha1" and "md5".
The default behaviour (no argument supplied) is "sha1".  Note that
"md5" is by far faster than "sha1".

### `oem get-provisioning-logs`

Works in any state. Displays the contents of the `KernelflingerLogs`
EFI variable. Useful if Kernelflinger crashes or hits an error at
manufacturing where no debug board or screen is connected.

### `oem set-storage <storage>`

Works in any state but is limited to `non-user` builds.  For devices
with both EMMC and UFS, this command is used to enforce one or the
other.  `STORAGE` value is limited to `emmc` and `ufs`.

### `fastboot oem crash-event-menu <0|1>`

Enable (1) or disable(0) [Crashmode](./crashmode.md).

### `oem set-watchdog-counter-max <value>`

Works in any device state but is limited to `non-user` builds.

This command sets the maximum number of crash events in a row before
[Crashmode](./crashmode.md) is displayed.  VALUE is comprised between
0 included and 255 included.

### `oem get-action-nonce <action>`

Works in any device state.
See. [Bootloader policy and Factory Reset Protection](./FRP.md).

Non-standard Variables
----------------------

### `secureboot`

Indicates whether UEFI Secure Boot is enabled. This is a pre-requisite
for Verified Boot.

### `product-name`

Reports the product_name field in DMI.

### `firmware`

Reports the current device firmware version from DMI. Combines the
values of the DMI `bios_vendor` and `bios_version` fields.

### `boot-state`

Indicates the device's color-coded boot state as per
[Google verified boot](https://source.android.com/security/verifiedboot/verified-boot.html)'s
specification. If the bootloader doesn't support Verified Boot,
`unknown` will be returned.

### `device-state`

Indicates the device's lock state as per
[Google verified boot](https://source.android.com/security/verifiedboot/verified-boot.html)'s
specification.

### `board`

Indicates the board information, combining the values of the DMI
`board_vendor`, `board_name`, and `board_version` fields.
