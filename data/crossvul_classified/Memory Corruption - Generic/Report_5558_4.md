# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5558_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5558_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.common import serializer
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone.openstack.common import jsonutils


CONF = config.CONF


# Header used to transmit the auth token
AUTH_TOKEN_HEADER = 'X-Auth-Token'


# Environment variable used to pass the request context
CONTEXT_ENV = wsgi.CONTEXT_ENV


# Environment variable used to pass the request params
PARAMS_ENV = wsgi.PARAMS_ENV

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,10 @@
 # License for the specific language governing permissions and limitations
 # under the License.
 
+import webob.dec
+
 from keystone.common import serializer
+from keystone.common import utils
 from keystone.common import wsgi
 from keystone import config
 from keystone import exception
@@ -164,3 +167,21 @@
         # Rewrites path to root if no path is given.
         elif not request.environ['PATH_INFO']:
             request.environ['PATH_INFO'] = '/'
+
+
+class RequestBodySizeLimiter(wsgi.Middleware):
+    """Limit the size of an incoming request."""
+
+    def __init__(self, *args, **kwargs):
+        super(RequestBodySizeLimiter, self).__init__(*args, **kwargs)
+
+    @webob.dec.wsgify(RequestClass=wsgi.Request)
+    def __call__(self, req):
+
+        if req.content_length > CONF.max_request_body_size:
+            raise exception.RequestTooLarge()
+        if req.content_length is None and req.is_body_readable:
+            limiter = utils.LimitingReader(req.body_file,
+                                           CONF.max_request_body_size)
+            req.body_file = limiter
+        return self.application
```
