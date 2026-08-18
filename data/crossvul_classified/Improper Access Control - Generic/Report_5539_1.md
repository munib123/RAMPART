# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 5539_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5539_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 204-244 of the vulnerable file.


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges")


class PolicyNotAuthorized(NotAuthorized):
    message = _("Policy doesn't allow %(action)s to be performed.")


class ImageNotAuthorized(NovaException):
    message = _("Not authorized for image %(image_id)s.")


class Invalid(NovaException):
    message = _("Unacceptable parameters.")
    code = 400


class InvalidSnapshot(Invalid):
    message = _("Invalid snapshot") + ": %(reason)s"


class VolumeUnattached(Invalid):
    message = _("Volume %(volume_id)s is not attached to anything")


class VolumeAttached(Invalid):
    message = _("Volume %(volume_id)s is still attached, detach volume first.")


class InvalidKeypair(Invalid):
    message = _("Keypair data is invalid")


class SfJsonEncodeFailure(NovaException):
    message = _("Failed to load data into json format")


class InvalidRequest(Invalid):
    message = _("The request is invalid.")

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,6 +223,20 @@
     message = _("Invalid snapshot") + ": %(reason)s"
 
 
+class InvalidBDM(Invalid):
+    message = _("Block Device Mapping is Invalid.")
+
+
+class InvalidBDMSnapshot(InvalidBDM):
+    message = _("Block Device Mapping is Invalid: "
+                "failed to get snapshot %(id)s.")
+
+
+class InvalidBDMVolume(InvalidBDM):
+    message = _("Block Device Mapping is Invalid: "
+                "failed to get volume %(id)s.")
+
+
 class VolumeUnattached(Invalid):
     message = _("Volume %(volume_id)s is not attached to anything")
 
```
