Installer
=========

Basically, Installer (aka. installer.efi binary) is a wrapper of the
[libfastboot](./fastboot.md).  It allows to flash a device using an
external storage (USB or SDCard for instance).  The external storage
must formatted using a filesystem supported by the BIOS (usually FAT16
or FAT32).

Installer supports all the Fastboot commands supported by
libfastboot.  For instance:

```bash
FS1:\> installer getvar all
Found 18 block io protocols
SDCard storage identified
[...]
SDCard storage identified
Found disk as block io 0 for logical unit 0
OEMLock not set, device is in provisioning mode
Couldn't read timeout variable; assuming default
err=Not Ready
Installer for fastboot transport layer selected
Starting command: 'getvar all'
GOT getvar all
(bootloader) unlocked: yes
(bootloader) secure: no
(bootloader) serialno: 001320FE4948
(bootloader) board: Circuitco MinnowBoard MAX REV A
(bootloader) device-state: unlocked
(bootloader) boot-state: unknown
(bootloader) firmware: Intel Corp. MNW2MAX1.X64.0090.R01.1601281003
(bootloader) product-name: Minnowboard Max D0 PLATFORM
(bootloader) secureboot: no
(bootloader) off-mode-charge: 1
(bootloader) has-slot:factory: no
(bootloader) partition-type:factory: ext4
(bootloader) partition-size:factory: 0x0000000000A00000
(bootloader) has-slot:config: no
(bootloader) partition-type:config: ext4
(bootloader) partition-size:config: 0x0000000000800000
(bootloader) has-slot:persistent: no
(bootloader) partition-type:persistent: ext4
(bootloader) partition-size:persistent: 0x0000000000100000
(bootloader) has-slot:userdata: no
(bootloader) partition-type:userdata: ext4
(bootloader) partition-size:userdata: 0x0000000221600000
(bootloader) has-slot:data: no
(bootloader) partition-type:data: ext4
(bootloader) partition-size:data: 0x0000000221600000
(bootloader) has-slot:cache: no
(bootloader) partition-type:cache: ext4
(bootloader) partition-size:cache: 0x0000000006400000
(bootloader) has-slot:vendor: no
(bootloader) partition-type:vendor: ext4
(bootloader) partition-size:vendor: 0x000000003E800000
(bootloader) has-slot:system_b: no
(bootloader) partition-type:system_b: ext4
(bootloader) partition-size:system_b: 0x00000000A0000000
(bootloader) has-slot:system_a: no
(bootloader) partition-type:system_a: ext4
(bootloader) partition-size:system_a: 0x00000000A0000000
(bootloader) has-slot:metadata: no
(bootloader) partition-type:metadata: none
(bootloader) partition-size:metadata: 0x0000000001000000
(bootloader) has-slot:misc: no
(bootloader) partition-type:misc: none
(bootloader) partition-size:misc: 0x0000000000100000
(bootloader) has-slot:recovery: no
(bootloader) partition-type:recovery: none
(bootloader) partition-size:recovery: 0x0000000001E00000
(bootloader) has-slot:boot_b: no
(bootloader) partition-type:boot_b: none
(bootloader) partition-size:boot_b: 0x0000000001E00000
(bootloader) has-slot:boot_a: no
(bootloader) partition-type:boot_a: none
(bootloader) partition-size:boot_a: 0x0000000001E00000
(bootloader) has-slot:bootloader2: no
(bootloader) partition-type:bootloader2: none
(bootloader) partition-size:bootloader2: 0x0000000003C00000
(bootloader) has-slot:bootloader: no
(bootloader) partition-type:bootloader: vfat
(bootloader) partition-size:bootloader: 0x0000000003C00000
(bootloader) max-download-size: 0x0000000010000000
(bootloader) battery-voltage:
(bootloader) version-bootloader: N/A
(bootloader) product: r2_cht_ffd_m
Command successfully executed
FS1:\> installer flash recovery recovery.img
Found 18 block io protocols
SDCard storage identified
[...]
SDCard storage identified
Found disk as block io 0 for logical unit 0
OEMLock not set, device is in provisioning mode
Couldn't read timeout variable; assuming default
err=Not Ready
Installer for fastboot transport layer selected
Starting command: 'flash recovery recovery.img'
GOT flash recovery recovery.img
Flashing recovery ...
Found label recovery in partition 4
sparse header : magic 52444E41, major 18767, minor 8516, fdhrsz 16752, chdrsz 140, bz 268468224
tot blk 14820014, tot chk 285212672
Flash done.
SENT OKAY
Command successfully executed
FS1:\>
```

With the `--batch <filename>` parameter, Installer sequentially runs
all the commands listed in FILENAME. The batch file format allows to
prefix the command with a list of attribute, example:

```conf
<[<ATTRIBUTE>]> flash system system.img
```

The only supported attribute is:
- 'o': the command is optional.  If the command fails to execute,
  Installer does not abort the flash process and continue with the
  next command.

Example:
```conf
[o] flash system system.img
```

Without any parameter, Installer assumes `--batch installer.cmd`.  It
allows to create a USB stick that will automatically flash the device
on boot.

Here is a `installer.cmd` file example:
```conf
flashing unlock
flash gpt gpt.bin
erase misc
erase persistent
erase metadata
format config
format cache
format data
flash vendor vendor.img
flash boot boot.img
flash recovery recovery.img
flash system system.img
flash bootloader bootloader
flash oemvars oemvars.txt
flashing lock
continue
```
