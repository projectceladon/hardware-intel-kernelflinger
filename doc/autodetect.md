Autodetect
==========

Overview
--------

Autodetect can be activated with the Kernelflinger `HAL_AUTODETECT`
compilation flag.

If Autodetect is enabled, Kernelflinger prepends some `androidboot`
parameter to the kernel command line:

- `androidboot.brand`: Combines the value of the DMI Board
  `manufacturer` and Product `manufacturer` fields.
- `androidboot.name`: Combines the value of the DMI Product
  `product_name` and Board `product_name`.
- `androidboot.device`: Combines the value of the DMI Board
  `product_name` and Board `version`.
- `androidboot.model`: same value than `androidboot.device`.

The init process is converting these command line parameters to
properties that can be used to identify the device product.

If Autodetect is enabled, Kernelflinger also loads the Blobstore
stored in the second stage area of the boot image, extract the OEMVARS
blob for the current device variant and flash these product dependent
EFI variables.

Blobstore
---------

Blobstore is a structure storing any kind of data inside the second
stage area of the bootimage. The data is organized as a dictionary in
which the key is the string: `<brand>/<product>/<device>`.
(Cf. [blobstore.c](../libkernelflinger/blobstore.c).

Blobstore current support the following data type: device tree blob,
OEMVARS (Cf. [Fastboot](./fastboot.md)) and Kernel command line
parameters.  Kernelflinger is using the OEMVARS type only.
