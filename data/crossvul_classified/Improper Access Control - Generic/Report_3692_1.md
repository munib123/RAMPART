# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3692_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3692_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 9-49 of the vulnerable file.

#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

import routes

from keystone import catalog
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token
from keystone.common import logging
from keystone.common import utils
from keystone.common import wsgi


class AdminRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        version_controller = VersionController('admin')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version')

        # Token Operations
        auth_controller = TokenController()
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,9 @@
 from keystone.common import logging
 from keystone.common import utils
 from keystone.common import wsgi
+
+
+LOG = logging.getLogger(__name__)
 
 
 class AdminRouter(wsgi.ComposingRouter):
@@ -275,7 +278,8 @@
 
                 # If the user is disabled don't allow them to authenticate
                 if not user_ref.get('enabled', True):
-                    raise exception.Forbidden(message='User has been disabled')
+                    LOG.warning('User %s is disabled' % user_id)
+                    raise exception.Unauthorized()
             except AssertionError as e:
                 raise exception.Unauthorized(e.message)
 
@@ -313,6 +317,14 @@
                 raise exception.Unauthorized()
 
             user_ref = old_token_ref['user']
+
+            # If the user is disabled don't allow them to authenticate
+            current_user_ref = self.identity_api.get_user(
+                                                    context=context,
+                                                    user_id=user_ref['id'])
+            if not current_user_ref.get('enabled', True):
+                LOG.warning('User %s is disabled' % user_ref['id'])
+                raise exception.Unauthorized()
 
             tenants = self.identity_api.get_tenants_for_user(context,
                                                              user_ref['id'])
```
