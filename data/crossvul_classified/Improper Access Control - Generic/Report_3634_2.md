# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3634_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3634_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 14-54 of the vulnerable file.

#    License for the specific language governing permissions and limitations
#    under the License.

"""The security groups extension."""

import urllib
from xml.dom import minidom

from webob import exc
import webob

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import compute
from nova import db
from nova import exception
from nova import flags
from nova import log as logging
from nova import utils


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS
authorize = extensions.extension_authorizer('compute', 'security_groups')


def make_rule(elem):
    elem.set('id')
    elem.set('parent_group_id')

    proto = xmlutil.SubTemplateElement(elem, 'ip_protocol')
    proto.text = 'ip_protocol'

    from_port = xmlutil.SubTemplateElement(elem, 'from_port')
    from_port.text = 'from_port'

    to_port = xmlutil.SubTemplateElement(elem, 'to_port')
    to_port.text = 'to_port'

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 from nova import exception
 from nova import flags
 from nova import log as logging
+from nova import quota
 from nova import utils
 
 
@@ -289,6 +290,10 @@
         group_name = group_name.strip()
         group_description = group_description.strip()
 
+        if quota.allowed_security_groups(context, 1) < 1:
+            msg = _("Quota exceeded, too many security groups.")
+            raise exc.HTTPBadRequest(explanation=msg)
+
         LOG.audit(_("Create Security Group %s"), group_name, context=context)
         self.compute_api.ensure_default_security_group(context)
         if db.security_group_exists(context, context.project_id, group_name):
@@ -374,6 +379,13 @@
 
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
