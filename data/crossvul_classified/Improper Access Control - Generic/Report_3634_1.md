# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3634_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3634_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 14-54 of the vulnerable file.

#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import webob

from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova.api.openstack import extensions
from nova.db.sqlalchemy import api as sqlalchemy_api
from nova import db
from nova import exception
from nova import quota


authorize = extensions.extension_authorizer('compute', 'quotas')


quota_resources = ['metadata_items', 'injected_file_content_bytes',
        'volumes', 'gigabytes', 'ram', 'floating_ips', 'instances',
        'injected_files', 'cores']


class QuotaTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('quota_set', selector='quota_set')
        root.set('id')

        for resource in quota_resources:
            elem = xmlutil.SubTemplateElement(root, resource)
            elem.text = resource

        return xmlutil.MasterTemplate(root, 1)


class QuotaSetsController(object):

    def _format_quota_set(self, project_id, quota_set):
        """Convert the quota object to a result dict"""

        result = dict(id=str(project_id))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
 
 quota_resources = ['metadata_items', 'injected_file_content_bytes',
         'volumes', 'gigabytes', 'ram', 'floating_ips', 'instances',
-        'injected_files', 'cores']
+        'injected_files', 'cores', 'security_groups', 'security_group_rules']
 
 
 class QuotaTemplate(xmlutil.TemplateBuilder):
```
