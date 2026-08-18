# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 2920_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2920_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 1-38 of the vulnerable file.

# Copyright (c) 2010-2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
from hashlib import sha1
import hmac
from httplib import HTTPConnection
from httplib import HTTPSConnection
import json
import swift
from time import gmtime
from time import strftime
from time import time
from traceback import format_exc
from urllib import quote
from urllib import unquote
from uuid import uuid4

from eventlet.timeout import Timeout
from eventlet import TimeoutError
from swift.common.swob import HTTPAccepted
from swift.common.swob import HTTPBadRequest
from swift.common.swob import HTTPConflict
from swift.common.swob import HTTPCreated
from swift.common.swob import HTTPForbidden
from swift.common.swob import HTTPMethodNotAllowed
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 
 import base64
 from hashlib import sha1
+from hashlib import sha512
 import hmac
 from httplib import HTTPConnection
 from httplib import HTTPSConnection
@@ -50,6 +51,8 @@
 from swift.common.utils import cache_from_env
 from swift.common.utils import get_logger
 from swift.common.utils import get_remote_client
+from swift.common.utils import HASH_PATH_PREFIX
+from swift.common.utils import HASH_PATH_SUFFIX
 from swift.common.utils import split_path
 from swift.common.utils import TRUE_VALUES
 from swift.common.utils import urlparse
@@ -289,6 +292,15 @@
                 env['swift.clean_acl'] = clean_acl
         return self.app(env, start_response)
 
+    def _get_concealed_token(self, token):
+        """Returns hashed token to be used as object name in Swift.
+
+        Tokens are stored in auth account but object names are visible in Swift
+        logs. Object names are hashed from token.
+        """
+        enc_key = "%s:%s:%s" % (HASH_PATH_PREFIX, token, HASH_PATH_SUFFIX)
+        return sha512(enc_key).hexdigest()
+
     def get_groups(self, env, token):
         """Get groups for the given token.
 
@@ -397,8 +409,9 @@
                         memcache_key, (time() + expires_from_now, groups),
                         time=expires_from_now)
             else:
+                object_name = self._get_concealed_token(token)
                 path = quote('/v1/%s/.token_%s/%s' %
-                             (self.auth_account, token[-1], token))
+                             (self.auth_account, object_name[-1], object_name))
                 resp = self.make_pre_authed_request(
                     env, 'GET', path).get_response(self.app)
                 if resp.status_int // 100 != 2:
@@ -1168,8 +1181,9 @@
                             (path, resp.status))
         candidate_token = resp.headers.get('x-object-meta-auth-token')
         if candidate_token:
+            object_name = self._get_concealed_token(candidate_token)
             path = quote('/v1/%s/.token_%s/%s' %
-                (self.auth_account, candidate_token[-1], candidate_token))
+                (self.auth_account, object_name[-1], object_name))
             resp = self.make_pre_authed_request(
                 req.environ, 'DELETE', path).get_response(self.app)
             if resp.status_int // 100 != 2 and resp.status_int != 404:
@@ -1318,8 +1332,9 @@
         expires = None
         candidate_token = resp.headers.get('x-object-meta-auth-token')
         if candidate_token:
+            object_name = self._get_concealed_token(candidate_token)
             path = quote('/v1/%s/.token_%s/%s' %
-                (self.auth_account, candidate_token[-1], candidate_token))
+                (self.auth_account, object_name[-1], object_name))
             delete_token = False
             try:
                 if req.headers.get('x-auth-new-token', 'false').lower() in \
@@ -1362,8 +1377,9 @@
             # Generate new token
             token = '%stk%s' % (self.reseller_prefix, uuid4().hex)
             # Save token info
+            object_name = self._get_concealed_token(token)
             path = quote('/v1/%s/.token_%s/%s' %
-                         (self.auth_account, token[-1], token))
+                         (self.auth_account, object_name[-1], object_name))
             try:
                 token_life = min(
                     int(req.headers.get('x-auth-token-lifetime',
@@ -1439,8 +1455,9 @@
                 if expires < time():
                     groups = None
         if not groups:
+            object_name = self._get_concealed_token(token)
             path = quote('/v1/%s/.token_%s/%s' %
-                         (self.auth_account, token[-1], token))
+                         (self.auth_account, object_name[-1], object_name))
             resp = self.make_pre_authed_request(
                 req.environ, 'GET', path).get_response(self.app)
             if resp.status_int // 100 != 2:
```
