# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in python
**Pair ID:** 4085_2
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4085_2`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```python
Lines 54-98 of the vulnerable file.

import tuf.keydb
import tuf.roledb
import tuf.formats

import securesystemslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.sig')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True


def get_signature_status(signable, role=None, repository_name='default',
    threshold=None, keyids=None):
  """
  <Purpose>
    Return a dictionary representing the status of the signatures listed in
    'signable'.  Given an object conformant to SIGNABLE_SCHEMA, a set of public
    keys in 'tuf.keydb', a set of roles in 'tuf.roledb', and a role,
    the status of these signatures can be determined.  This method will iterate
    the signatures in 'signable' and enumerate all the keys that are valid,
    invalid, unrecognized, or unauthorized.

  <Arguments>
    signable:
      A dictionary containing a list of signatures and a 'signed' identifier.
      signable = {'signed': 'signer',
                  'signatures': [{'keyid': keyid,
                                  'sig': sig}]}

      Conformant to tuf.formats.SIGNABLE_SCHEMA.

    role:
      TUF role (e.g., 'root', 'targets', 'snapshot').

    threshold:
      Rather than reference the role's threshold as set in tuf.roledb.py, use
      the given 'threshold' to calculate the signature status of 'signable'.
      'threshold' is an integer value that sets the role's threshold value, or
      the minimum number of signatures needed for metadata to be considered
      fully signed.

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,11 +71,23 @@
   """
   <Purpose>
     Return a dictionary representing the status of the signatures listed in
-    'signable'.  Given an object conformant to SIGNABLE_SCHEMA, a set of public
-    keys in 'tuf.keydb', a set of roles in 'tuf.roledb', and a role,
-    the status of these signatures can be determined.  This method will iterate
-    the signatures in 'signable' and enumerate all the keys that are valid,
-    invalid, unrecognized, or unauthorized.
+    'signable'. Signatures in the returned dictionary are identified by the
+    signature keyid and can have a status of either:
+
+    * bad -- Invalid signature
+    * good -- Valid signature from key that is available in 'tuf.keydb', and is
+      authorized for the passed role as per 'tuf.roledb' (authorization may be
+      overwritten by passed 'keyids').
+    * unknown -- Signature from key that is not available in 'tuf.keydb', or if
+      'role' is None.
+    * unknown signing schemes -- Signature from key with unknown signing
+      scheme.
+    * untrusted -- Valid signature from key that is available in 'tuf.keydb',
+      but is not trusted for the passed role as per 'tuf.roledb' or the passed
+      'keyids'.
+
+    NOTE: The result may contain duplicate keyids or keyids that reference the
+    same key, if 'signable' lists multiple signatures from the same key.
 
   <Arguments>
     signable:
@@ -87,7 +99,7 @@
       Conformant to tuf.formats.SIGNABLE_SCHEMA.
 
     role:
-      TUF role (e.g., 'root', 'targets', 'snapshot').
+      TUF role string (e.g. 'root', 'targets', 'snapshot' or timestamp).
 
     threshold:
       Rather than reference the role's threshold as set in tuf.roledb.py, use
@@ -133,22 +145,6 @@
 
   # The signature status dictionary returned.
   signature_status = {}
-
-  # The fields of the signature_status dict, where each field stores keyids.  A
-  # description of each field:
-  #
-  # good_sigs = keys confirmed to have produced 'sig' using 'signed', which are
-  # associated with 'role';
-  #
-  # bad_sigs = negation of good_sigs;
-  #
-  # unknown_sigs = keys not found in the 'keydb' database;
-  #
-  # untrusted_sigs = keys that are not in the list of keyids associated with
-  # 'role';
-  #
-  # unknown_signing_scheme = signing schemes specified in keys that are
-  # unsupported;
   good_sigs = []
   bad_sigs = []
   unknown_sigs = []
@@ -240,18 +236,26 @@
     keyids=None):
   """
   <Purpose>
-    Verify whether the authorized signatures of 'signable' meet the minimum
-    required by 'role'.  Authorized signatures are those with valid keys
-    associated with 'role'.  'signable' must conform to SIGNABLE_SCHEMA
-    and 'role' must not equal 'None' or be less than zero.
+    Verify that 'signable' has a valid threshold of authorized signatures
+    identified by unique keyids. The threshold and whether a keyid is
+    authorized is determined by querying the 'threshold' and 'keyids' info for
+    the passed 'role' in 'tuf.roledb'. Both values can be overwritten by
+    passing the 'threshold' or 'keyids' arguments.
+
+    NOTE:
+    - Signatures with identical authorized keyids only count towards the
+      threshold once.
+    - Signatures with different authorized keyids each count towards the
+      threshold, even if the keyids identify the same key.
 
   <Arguments>
     signable:
-      A dictionary containing a list of signatures and a 'signed' identifier.
+      A dictionary containing a list of signatures and a 'signed' identifier
+      that conforms to SIGNABLE_SCHEMA, e.g.:
       signable = {'signed':, 'signatures': [{'keyid':, 'method':, 'sig':}]}
 
     role:
-      TUF role (e.g., 'root', 'targets', 'snapshot').
+      TUF role string (e.g. 'root', 'targets', 'snapshot' or timestamp).
 
     threshold:
       Rather than reference the role's threshold as set in tuf.roledb.py, use
@@ -278,8 +282,8 @@
     get_signature_status() will be caught here and re-raised.
 
   <Returns>
-    Boolean.  True if the number of good signatures >= the role's threshold,
-    False otherwise.
+    Boolean.  True if the number of good unique (by keyid) signatures >= the
+    role's threshold, False otherwise.
   """
 
   tuf.formats.SIGNABLE_SCHEMA.check_match(signable)
@@ -303,7 +307,7 @@
   if threshold is None or threshold <= 0: #pragma: no cover
     raise securesystemslib.exceptions.Error("Invalid threshold: " + repr(threshold))
 
-  return len(good_sigs) >= threshold
+  return len(set(good_sigs)) >= threshold
 
 
 
```
