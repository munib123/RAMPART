# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5559_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5559_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 5-45 of the vulnerable file.

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid
import routes
import json

from keystone import config
from keystone import catalog
from keystone.common import cms
from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.openstack.common import timeutils
from keystone import policy
from keystone import token


LOG = logging.getLogger(__name__)


class AdminRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        version_controller = VersionController('admin')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version')

        # Token Operations
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 from keystone import catalog
 from keystone.common import cms
 from keystone.common import logging
+from keystone.common import utils
 from keystone.common import wsgi
 from keystone import exception
 from keystone import identity
@@ -31,6 +32,8 @@
 
 
 LOG = logging.getLogger(__name__)
+MAX_PARAM_SIZE = config.CONF.max_param_size
+MAX_TOKEN_SIZE = config.CONF.max_token_size
 
 
 class AdminRouter(wsgi.ComposingRouter):
@@ -288,9 +291,23 @@
 
         if 'passwordCredentials' in auth:
             user_id = auth['passwordCredentials'].get('userId', None)
+            if user_id and len(user_id) > MAX_PARAM_SIZE:
+                raise exception.ValidationSizeError(attribute='userId',
+                                                    size=MAX_PARAM_SIZE)
             username = auth['passwordCredentials'].get('username', '')
+            if len(username) > MAX_PARAM_SIZE:
+                raise exception.ValidationSizeError(attribute='username',
+                                                    size=MAX_PARAM_SIZE)
             password = auth['passwordCredentials'].get('password', '')
+            max_pw_size = utils.MAX_PASSWORD_LENGTH
+            if len(password) > max_pw_size:
+                raise exception.ValidationSizeError(attribute='password',
+                                                    size=max_pw_size)
+
             tenant_name = auth.get('tenantName', None)
+            if tenant_name and len(tenant_name) > MAX_PARAM_SIZE:
+                raise exception.ValidationSizeError(attribute='tenantName',
+                                                    size=MAX_PARAM_SIZE)
 
             if username:
                 try:
@@ -302,6 +319,9 @@
 
             # more compat
             tenant_id = auth.get('tenantId', None)
+            if tenant_id and len(tenant_id) > MAX_PARAM_SIZE:
+                raise exception.ValidationSizeError(attribute='tenantId',
+                                                    size=MAX_PARAM_SIZE)
             if tenant_name:
                 try:
                     tenant_ref = self.identity_api.get_tenant_by_name(
@@ -342,7 +362,14 @@
                 catalog_ref = {}
         elif 'token' in auth:
             old_token = auth['token'].get('id', None)
+
+            if len(old_token) > MAX_TOKEN_SIZE:
+                raise exception.ValidationSizeError(attribute='token',
+                                                    size=MAX_TOKEN_SIZE)
             tenant_name = auth.get('tenantName')
+            if tenant_name and len(tenant_name) > MAX_PARAM_SIZE:
+                raise exception.ValidationSizeError(attribute='tenantName',
+                                                    size=MAX_PARAM_SIZE)
 
             try:
                 old_token_ref = self.token_api.get_token(context=context,
```
