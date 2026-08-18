# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 3761_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3761_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 3-43 of the vulnerable file.

# Copyright 2012 OpenStack LLC
#
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

from keystone import catalog
from keystone.common import logging
from keystone.common import utils
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

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,6 @@
 
 from keystone import catalog
 from keystone.common import logging
-from keystone.common import utils
 from keystone.common import wsgi
 from keystone import exception
 from keystone import identity
@@ -284,6 +283,11 @@
                 if not user_ref.get('enabled', True):
                     LOG.warning('User %s is disabled' % user_id)
                     raise exception.Unauthorized()
+
+                # If the tenant is disabled don't allow them to authenticate
+                if tenant_ref and not tenant_ref.get('enabled', True):
+                    LOG.warning('Tenant %s is disabled' % tenant_id)
+                    raise exception.Unauthorized()
             except AssertionError as e:
                 raise exception.Unauthorized(e.message)
 
@@ -354,6 +358,14 @@
                 tenant_ref = None
                 metadata_ref = {}
                 catalog_ref = {}
+            except exception.MetadataNotFound:
+                metadata_ref = {}
+                catalog_ref = {}
+
+            # If the tenant is disabled don't allow them to authenticate
+            if tenant_ref and not tenant_ref.get('enabled', True):
+                LOG.warning('Tenant %s is disabled' % tenant_id)
+                raise exception.Unauthorized()
 
             token_ref = self.token_api.create_token(
                 context, token_id, dict(id=token_id,
```
