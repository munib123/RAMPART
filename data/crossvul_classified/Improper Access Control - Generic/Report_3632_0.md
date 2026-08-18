# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3632_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3632_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 24-64 of the vulnerable file.


import base64
import re
import time
import urllib

from nova.api.ec2 import ec2utils
from nova.api.ec2 import inst_state
from nova.api import validator
from nova import block_device
from nova import compute
from nova.compute import instance_types
from nova.compute import vm_states
from nova import crypto
from nova import db
from nova import exception
from nova import flags
from nova.image import s3
from nova import log as logging
from nova import network
from nova import utils
from nova import volume


FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


def validate_ec2_id(val):
    if not validator.validate_str()(val):
        raise exception.InvalidInstanceIDMalformed(val)
    try:
        ec2utils.ec2_id_to_id(val)
    except exception.InvalidEc2Id:
        raise exception.InvalidInstanceIDMalformed(val)


def _gen_key(context, user_id, key_name):
    """Generate a key

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,7 @@
 from nova.image import s3
 from nova import log as logging
 from nova import network
+from nova import quota
 from nova import utils
 from nova import volume
 
@@ -725,6 +726,13 @@
                     raise exception.EC2APIError(err % values_for_rule)
                 postvalues.append(values_for_rule)
 
+        allowed = quota.allowed_security_group_rules(context,
+                                                   security_group['id'],
+                                                   1)
+        if allowed < 1:
+            msg = _("Quota exceeded, too many security group rules.")
+            raise exception.EC2APIError(msg)
+
         rule_ids = []
         for values_for_rule in postvalues:
             security_group_rule = db.security_group_rule_create(
@@ -781,6 +789,10 @@
         if db.security_group_exists(context, context.project_id, group_name):
             msg = _('group %s already exists')
             raise exception.EC2APIError(msg % group_name)
+
+        if quota.allowed_security_groups(context, 1) < 1:
+            msg = _("Quota exceeded, too many security groups.")
+            raise exception.EC2APIError(msg)
 
         group = {'user_id': context.user_id,
                  'project_id': context.project_id,
```
