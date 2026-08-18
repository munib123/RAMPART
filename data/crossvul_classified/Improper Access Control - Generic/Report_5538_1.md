# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 5538_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5538_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 290-330 of the vulnerable file.



# Cannot be templated as the error syntax varies.
# msg needs to be constructed when raised.
class InvalidParameterValue(Invalid):
    message = _("%(err)s")


class InvalidAggregateAction(Invalid):
    message = _("Cannot perform action '%(action)s' on aggregate "
                "%(aggregate_id)s. Reason: %(reason)s.")


class InvalidGroup(Invalid):
    message = _("Group not valid. Reason: %(reason)s")


class InstanceInvalidState(Invalid):
    message = _("Instance %(instance_uuid)s in %(attr)s %(state)s. Cannot "
                "%(method)s while the instance is in this state.")


class InstanceNotRunning(Invalid):
    message = _("Instance %(instance_id)s is not running.")


class InstanceNotSuspended(Invalid):
    message = _("Instance %(instance_id)s is not suspended.")


class InstanceNotInRescueMode(Invalid):
    message = _("Instance %(instance_id)s is not in rescue mode")


class InstanceSuspendFailure(Invalid):
    message = _("Failed to suspend instance") + ": %(reason)s"


class InstanceResumeFailure(Invalid):
    message = _("Failed to resume server") + ": %(reason)s."

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -309,6 +309,20 @@
                 "%(method)s while the instance is in this state.")
 
 
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
 class InstanceNotRunning(Invalid):
     message = _("Instance %(instance_id)s is not running.")
 
```
