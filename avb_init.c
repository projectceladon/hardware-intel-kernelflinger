#include "avb_init.h"

//Global AvbOps data structure
static AvbOps *ops = NULL;

AvbOps *avb_init(void)
{
	avb_print("UEFI AVB-based bootloader\n");

	ops = uefi_avb_ops_new();
	if (!ops) {
		avb_fatal("Error allocating AvbOps.\n");
		return NULL;
	}

	return ops;
}
