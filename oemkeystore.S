	.globl oem_keystore_table
	.data
	.align 16
	.type	oem_keystore_table, @object
	.size	oem_keystore_table, 4
	.section .oem_keystore, "a", @progbits
oem_keystore_table:
	.long	oem_keystore_priv_end - oem_keystore_priv
	.long	oem_key_priv_end - oem_key_priv
	.long	oem_keystore_priv - oem_keystore_table
	.long	oem_key_priv - oem_keystore_table
	.data
	.align	1
	.type	oem_keystore_priv, @object
	.size	oem_keystore_priv, oem_keystore_priv_end-oem_keystore_priv
	.section .oem_keystore, "a", @progbits
oem_keystore_priv:
.incbin OEM_KEYSTORE_FILE
oem_keystore_priv_end:
	.data
	.align	1
	.type	oem_key_priv, @object
	.size	oem_key_priv, oem_key_priv_end-oem_key_priv
	.section .oem_keystore, "a", @progbits
oem_key_priv:
.incbin OEM_KEY_FILE
oem_key_priv_end:

