# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3633_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3633_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 9-49 of the vulnerable file.

#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""The security groups extension."""

import urllib
from webob import exc
import webob

from nova import compute
from nova import db
from nova import exception
from nova import flags
from nova import log as logging
from nova import rpc
from nova import utils
from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.compute import power_state

from xml.dom import minidom


LOG = logging.getLogger("nova.api.contrib.security_groups")
FLAGS = flags.FLAGS


class SecurityGroupController(object):
    """The Security group API controller for the OpenStack API."""

    def __init__(self):
        self.compute_api = compute.API()
        super(SecurityGroupController, self).__init__()

    def _format_security_group_rule(self, context, rule):
        sg_rule = {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,7 @@
 from nova import log as logging
 from nova import rpc
 from nova import utils
+from nova import quota
 from nova.api.openstack import common
 from nova.api.openstack import extensions
 from nova.api.openstack import wsgi
@@ -136,6 +137,10 @@
         group_name = group_name.strip()
         group_description = group_description.strip()
 
+        if quota.allowed_security_groups(context, 1) < 1:
+            msg = _("Quota exceeded, too many security groups.")
+            raise exc.HTTPBadRequest(explanation=msg)
+
         LOG.audit(_("Create Security Group %s"), group_name, context=context)
         self.compute_api.ensure_default_security_group(context)
         if db.security_group_exists(context, context.project_id, group_name):
@@ -217,6 +222,13 @@
 
         if self._security_group_rule_exists(security_group, values):
             msg = _('This rule already exists in group %s') % parent_group_id
+            raise exc.HTTPBadRequest(explanation=msg)
+
+        allowed = quota.allowed_security_group_rules(context,
+                                                   parent_group_id,
+                                                   1)
+        if allowed < 1:
+            msg = _("Quota exceeded, too many security group rules.")
             raise exc.HTTPBadRequest(explanation=msg)
 
         security_group_rule = db.security_group_rule_create(context, values)
```
