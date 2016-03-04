Bootloader Policy and Factory Reset Protection
==============================================

[Google's verified boot](https://source.android.com/security/verifiedboot/verified-boot.html)
(GVB) specification and Google Factory Reset Protection (FRP) for
Android<sup>TM</sup> define a set of security protocols for ensuring
system integrity and dis-incentivising device theft, respectively.

There are legitimate reasons to unlock the bootloader without knowing
the screen unlock PIN; specifically RMAs. An RMA processing center
should be able to unlock device flashing restrictions in Fastboot and
return the device to a factory pristine state without requiring the
user to disclose their screen unlock PIN or potentially opening their
user data to compromise.

This documentation describes the solution for defining a class A
device and a mechanism that allow for unlocking a device for RMA
regardless of FRP or class A status. It meets Google FRP security
requirements by ensuring that there is no single skeleton key to
unlock devices if all security considerations are implemented. It also
allows devices to be provisioned so that the entity with unlock
authority could be Vendor, the OEM, ODM, a carrier, or an enterprise
organization.

Device User Experience
----------------------

1. User boots the device to Fastboot
2. User obtains an action challenge
```bash
fastboot oem get-action-nonce force-unlock
```
3. User gives the challenge to the action authorization agent and
   receives an action authorization token file (details later)
4. User flashes the action authorization token
```bash
fastboot flash action-authorization token_file
```
5. Fastboot performs the authorized action

Implementation
--------------

The OEM action authorization protocol is a simple challenge response
where the device's Fastboot generates a one-time-nonce, the OEM action
authorization agent signs the nonce and approved action using its
private override authorization key (OAK) to generate an authorization
token, and then the device's Fastboot validates the action
authorization token and executes the action.

Override Authorization Key
--------------------------

The override authorization key (OAK) is a public key that is set in
the device during manufacturing and that is used to validate action
authorization tokens. If an OAK is not set, then all action
authorization features are disabled and default bootloader and
Fastboot behavior specified in GVB and FRP is in effect. Since the OAK
is capable of overriding the class A and FRP policies, it is important
to ensure that it cannot be changed by unauthorized code, which would
change the identity of who can override policy.

The OAK may act as a validation root certificate if the certificate
authority attribute of the certificate is "true" -- standard X.509v3
certificate handling. This means that the OAK can be used to issue
certificates that are also able to sign action authorization
tokens. This is the preferred method of setting the OAK in cases where
multiple entities need the ability to issue action authorization
tokens without having access to a single key.

OAK is stored as the `OAK` time-based authenticated EFI variable under
the Fastboot GUID of `1ac80a82-4f0c-456b-9a99-debeb431fcc1`.  The
content of this variable is the SHA256 sum of the OAK certificate.

Bootloader Policy Mask
----------------------

Bootloader policy mask (BPM) is a set of 64 boolean policy flags. If a
BPM is not set, then Fastboot defaults to a policy matching a BPM
value of zero. If a BPM value is set, a one bit indicates the
corresponding policy is active.

The BPM is set in the device during manufacturing.

| Policy Name      | Bit(s)  | Description
|------------------|---------|----------------------------------------------
| CLASS\_A\_DEVICE | 0       | If set, the bootloader enforces the behavior defined by GVB for class A devices.
| MIN\_BOOT\_STATE | 1-2     | Minimal boot state required to boot the device (0 for red, 1 for orange, 2 for yellow and 3 for green)

BPM is stored as the `BPM` time-based authenticated EFI variable under
the Fastboot GUID of `1ac80a82-4f0c-456b-9a99-debeb431fcc1`.

Generating One-Time-Nonce
-------------------------

The one-time action authorization nonce has the form
"<version>:<serial number>:<8 bit action id>:<16 client random bytes>"
with all fields hex encoded. It is generated when the `fastboot oem
get-action-nonce <action>` command is used. Fastboot saves the value
for a limited amount of time before it expires. Each time the command
is run a new value is generated and previous value is overwritten. The
value is not stored persistently. If Fastboot is restarted, the old
nonce is no longer valid.

The following actions are defined.

| Name         | Action ID | Description
|--------------|-----------|------------
| Force unlock | 0x00      | Makes Kernelfliner execute the Fastboot `flashing unlock` command as if the "enable oem unlock" developer option is enabled. All standard GVB properties apply, including secure erase of the user data partition.

The version field is a one byte value. It must be zero for the current
version.

Creating an Action Authorization Token
--------------------------------------

An action authorization token is generated by signing the action
authorization nonce with the OAK. The token is a PKCS #7 signed
document, where the body takes the form "<version>:<serial number>:<8
bit action id>:<16 client random bytes>:<16 auth agent random bytes>"
with all fields hex encoded. The auth agent random bytes added when
creating the authorization is to prevent an attacker from mounting an
attack by supplying known plain-text values.

The token must contain all certificates required to validate the
signature chain of the token.

The action authorization agent must verify that the nonce is exactly
in the prescribed format.

The action authorization agent must verify that the action ID in nonce
is a recognized value.

If possible, the action authorization agent should verify that the
serial number is valid.

Flashing the Action Authorization Token
---------------------------------------

The authorization token is sent to Fastboot using the special
"action-authorization" flash target. Fastboot verifies that the token
is valid, invalidates the current one-time-nonce, and executes the
authorized action.

Fastboot must validate that there is no extra data after parsing the
token.

Fastboot must verify that the signature's certificate chains to the
OAK set at manufacturing.

Fastboot must verify that all values in the token body have the
prescribed values.

Fastboot must verify that the value returned by the "oem
get-action-nonce <action>" command matches the value in the token body
and the nonce has not expired.
