# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3693_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3693_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 7-47 of the vulnerable file.

# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Main entry point into the Identity service."""

import uuid
import urllib
import urlparse

from keystone import config
from keystone import exception
from keystone import policy
from keystone import token
from keystone.common import manager
from keystone.common import wsgi


CONF = config.CONF


class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)


class Driver(object):
    """Interface description for an Identity driver."""
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,11 +24,14 @@
 from keystone import exception
 from keystone import policy
 from keystone import token
+from keystone.common import logging
 from keystone.common import manager
 from keystone.common import wsgi
 
 
 CONF = config.CONF
+
+LOG = logging.getLogger(__name__)
 
 
 class Manager(manager.Manager):
@@ -418,7 +421,16 @@
         return self.update_user(context, user_id, user)
 
     def set_user_password(self, context, user_id, user):
-        return self.update_user(context, user_id, user)
+        user_ref = self.update_user(context, user_id, user)
+        try:
+            for token_id in self.token_api.list_tokens(context, user_id):
+                self.token_api.delete_token(context, token_id)
+        except exception.NotImplemented:
+            # The password has been changed but tokens remain valid for
+            # backends that can't list tokens for users
+            LOG.warning('Password changed for %s, but existing tokens remain '
+                        'valid' % user_id)
+        return user_ref
 
     def update_user_tenant(self, context, user_id, user):
         """Update the default tenant."""
```
