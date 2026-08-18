# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4126_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4126_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 90-109 of the vulnerable file.

# This configuration is for indicating how consistent files should be created.
# There are two options: "copy" and "hard_link".  For "copy", the consistent
# file with be a copy of root.json.  This approach will require the most disk
# space out of the two options.  For "hard_link", the latest root.json will be
# a hard link to 2.root.json (for example).  This approach is more efficient in
# terms of disk space usage.  By default, we use 'copy'.
CONSISTENT_METHOD = 'copy'

# A setting for the instances where a default hashing algorithm is needed.
# This setting is currently used to calculate the path hash prefixes of hashed
# bin delegations, and digests of targets filepaths.  The other instances
# (e.g., digest of files) that require a hashing algorithm rely on settings in
# the securesystemslib external library.
DEFAULT_HASH_ALGORITHM = 'sha256'

# The client's update procedure (contained within a while-loop) can potentially
# hog the CPU.  The following setting can be used to force the update sequence
# to suspend execution for a specified amount of time.  See
# theupdateframework/tuf/issue#338.
SLEEP_BEFORE_ROUND = None
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,3 +107,7 @@
 # to suspend execution for a specified amount of time.  See
 # theupdateframework/tuf/issue#338.
 SLEEP_BEFORE_ROUND = None
+
+# Maximum number of root metadata file rotations we should perform in order to
+# prevent a denial-of-service (DoS) attack.
+MAX_NUMBER_ROOT_ROTATIONS = 2**5
```
