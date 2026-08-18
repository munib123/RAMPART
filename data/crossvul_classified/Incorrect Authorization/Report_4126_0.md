# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4126_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4126_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 128-168 of the vulnerable file.

import fnmatch
import copy
import warnings

import tuf
import tuf.download
import tuf.formats
import tuf.settings
import tuf.keydb
import tuf.log
import tuf.mirrors
import tuf.roledb
import tuf.sig
import tuf.exceptions

import securesystemslib.hash
import securesystemslib.keys
import securesystemslib.util
import six
import iso8601

# The Timestamp role does not have signed metadata about it; otherwise we
# would need an infinite regress of metadata. Therefore, we use some
# default, but sane, upper file length for its metadata.
DEFAULT_TIMESTAMP_UPPERLENGTH = tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH

# The Root role may be updated without knowing its version number if
# top-level metadata cannot be safely downloaded (e.g., keys may have been
# revoked, thus requiring a new Root file that includes the updated keys)
# and 'unsafely_update_root_if_necessary' is True.
# We use some default, but sane, upper file length for its metadata.
DEFAULT_ROOT_UPPERLENGTH = tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.client.updater')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,6 +145,7 @@
 import securesystemslib.util
 import six
 import iso8601
+import requests.exceptions
 
 # The Timestamp role does not have signed metadata about it; otherwise we
 # would need an infinite regress of metadata. Therefore, we use some
@@ -1125,28 +1126,58 @@
       None.
     """
 
-    # Retrieve the latest, remote root.json.
-    latest_root_metadata_file = self._get_metadata_file(
-        'root', 'root.json', DEFAULT_ROOT_UPPERLENGTH, None)
-
-    latest_root_metadata = securesystemslib.util.load_json_string(
-        latest_root_metadata_file.read().decode('utf-8'))
-
-
-    next_version = current_root_metadata['version'] + 1
-    latest_version = latest_root_metadata['signed']['version']
-
-    # update from the next version of root up to (and including) the latest
-    # version.  For example:
-    # current = version 1
-    # latest = version 3
-    # update from 1.root.json to 3.root.json.
-    for version in range(next_version, latest_version + 1):
-      # Temporarily set consistent snapshot. Will be updated to whatever is set
-      # in the latest root.json after running through the intermediates with
-      # _update_metadata().
-      self.consistent_snapshot = True
-      self._update_metadata('root', DEFAULT_ROOT_UPPERLENGTH, version=version)
+    def neither_403_nor_404(mirror_error):
+      if isinstance(mirror_error, requests.exceptions.HTTPError):
+        if mirror_error.response.status_code in {403, 404}:
+          return False
+      return True
+
+    # Temporarily set consistent snapshot. Will be updated to whatever is set
+    # in the latest root.json after running through the intermediates with
+    # _update_metadata().
+    self.consistent_snapshot = True
+
+    # Following the spec, try downloading the N+1th root for a certain maximum
+    # number of times.
+    lower_bound = current_root_metadata['version'] + 1
+    upper_bound = lower_bound + tuf.settings.MAX_NUMBER_ROOT_ROTATIONS
+
+    # Try downloading the next root.
+    for next_version in range(lower_bound, upper_bound):
+      try:
+        # Thoroughly verify it.
+        self._update_metadata('root', DEFAULT_ROOT_UPPERLENGTH,
+            version=next_version)
+      # When we run into HTTP 403/404 error from ALL mirrors, break out of
+      # loop, because the next root metadata file is most likely missing.
+      except tuf.exceptions.NoWorkingMirrorError as exception:
+        for mirror_error in exception.mirror_errors.values():
+          # Otherwise, reraise the error, because it is not a simple HTTP
+          # error.
+          if neither_403_nor_404(mirror_error):
+            logging.exception('Misc error for root version '+str(next_version))
+            raise
+          else:
+            # Calling this function should give us a detailed stack trace
+            # including an HTTP error code, if any.
+            logging.exception('HTTP error for root version '+str(next_version))
+        # If we are here, then we ran into only 403 / 404 errors, which are
+        # good reasons to suspect that the next root metadata file does not
+        # exist.
+        break
+
+      # Ensure that the role and key information of the top-level roles is the
+      # latest.  We do this whether or not Root needed to be updated, in order
+      # to ensure that, e.g., the entries in roledb for top-level roles are
+      # populated with expected keyid info so that roles can be validated.  In
+      # certain circumstances, top-level metadata might be missing because it
+      # was marked obsolete and deleted after a failed attempt, and thus we
+      # should refresh them here as a protective measure.  See Issue #736.
+      self._rebuild_key_and_role_db()
+
+    # Set our consistent snapshot property to what the latest root has said.
+    self.consistent_snapshot = \
+        self.metadata['current']['root']['consistent_snapshot']
 
 
 
```
