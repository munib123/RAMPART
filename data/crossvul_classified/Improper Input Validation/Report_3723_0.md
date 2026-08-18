# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3723_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3723_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 11-51 of the vulnerable file.

#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Forms used for Horizon's auth mechanisms.
"""

import logging

from django import shortcuts
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.utils.translation import ugettext as _
from keystoneclient import exceptions as keystone_exceptions

from horizon import api
from horizon import base
from horizon import exceptions
from horizon import forms
from horizon import users


LOG = logging.getLogger(__name__)


def _set_session_data(request, token):
    request.session['serviceCatalog'] = token.serviceCatalog
    request.session['tenant'] = token.tenant['name']
    request.session['tenant_id'] = token.tenant['id']
    request.session['token'] = token.id
    request.session['user_name'] = token.user['name']
    request.session['user_id'] = token.user['id']
    request.session['roles'] = token.user['roles']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
 from django.conf import settings
 from django.contrib import messages
 from django.contrib.auth import REDIRECT_FIELD_NAME
+from django.utils.http import same_origin
 from django.utils.translation import ugettext as _
 from keystoneclient import exceptions as keystone_exceptions
 
@@ -94,7 +95,13 @@
         request.session['region_endpoint'] = endpoint
         request.session['region_name'] = region_name
 
-        redirect_to = request.REQUEST.get(REDIRECT_FIELD_NAME, "")
+        redirect_to = request.REQUEST.get(REDIRECT_FIELD_NAME, None)
+        # Make sure the requested redirect matches the protocol,
+        # domain, and port of this request
+        if redirect_to and not same_origin(
+                request.build_absolute_uri(redirect_to),
+                request.build_absolute_uri()):
+            redirect_to = None
 
         if data.get('tenant', None):
             try:
```
