# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3633_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3633_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 25-65 of the vulnerable file.

import base64
import os
import re
import shutil
import tempfile
import time
import urllib

from nova import block_device
from nova import compute
from nova import context

from nova import crypto
from nova import db
from nova import exception
from nova import flags
from nova import ipv6
from nova import log as logging
from nova import network
from nova import rpc
from nova import utils
from nova import volume
from nova.api.ec2 import ec2utils
from nova.compute import instance_types
from nova.compute import vm_states
from nova.image import s3


FLAGS = flags.FLAGS
flags.DECLARE('dhcp_domain', 'nova.network.manager')
flags.DECLARE('service_down_time', 'nova.scheduler.driver')

LOG = logging.getLogger("nova.api.cloud")


def _gen_key(context, user_id, key_name):
    """Generate a key

    This is a module level method because it is slow and we need to defer
    it into a process pool."""
    # NOTE(vish): generating key pair is slow so check for legal
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,7 @@
 from nova import log as logging
 from nova import network
 from nova import rpc
+from nova import quota
 from nova import utils
 from nova import volume
 from nova.api.ec2 import ec2utils
@@ -856,6 +857,13 @@
                     raise exception.ApiError(_(err) % values_for_rule)
                 postvalues.append(values_for_rule)
 
+        allowed = quota.allowed_security_group_rules(context,
+                                                   security_group['id'],
+                                                   1)
+        if allowed < 1:
+            msg = _("Quota exceeded, too many security group rules.")
+            raise exception.ApiError(msg)
+
         for values_for_rule in postvalues:
             security_group_rule = db.security_group_rule_create(
                     context,
@@ -907,6 +915,10 @@
         self.compute_api.ensure_default_security_group(context)
         if db.security_group_exists(context, context.project_id, group_name):
             raise exception.ApiError(_('group %s already exists') % group_name)
+
+        if quota.allowed_security_groups(context, 1) < 1:
+            msg = _("Quota exceeded, too many security groups.")
+            raise exception.ApiError(msg)
 
         group = {'user_id': context.user_id,
                  'project_id': context.project_id,
```
