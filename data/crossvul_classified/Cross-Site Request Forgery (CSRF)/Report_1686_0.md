# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1686_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1686_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

"""Base Tornado handlers for the notebook server."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import functools
import json
import logging
import os
import re
import sys
import traceback
try:
    # py3
    from http.client import responses
except ImportError:
    from httplib import responses

from jinja2 import TemplateNotFound
from tornado import web

from tornado import gen
from tornado.log import app_log


import IPython
from IPython.utils.sysinfo import get_sys_info

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,6 @@
 
 import functools
 import json
-import logging
 import os
 import re
 import sys
@@ -15,6 +14,10 @@
     from http.client import responses
 except ImportError:
     from httplib import responses
+try:
+    from urllib.parse import urlparse # Py 3
+except ImportError:
+    from urlparse import urlparse # Py 2
 
 from jinja2 import TemplateNotFound
 from tornado import web
@@ -320,6 +323,50 @@
 class APIHandler(IPythonHandler):
     """Base class for API handlers"""
     
+    def check_origin(self):
+        """Check Origin for cross-site API requests.
+        
+        Copied from WebSocket with changes:
+        
+        - allow unspecified host/origin (e.g. scripts)
+        """
+        if self.allow_origin == '*':
+            return True
+
+        host = self.request.headers.get("Host")
+        origin = self.request.headers.get("Origin")
+
+        # If no header is provided, assume it comes from a script/curl.
+        # We are only concerned with cross-site browser stuff here.
+        if origin is None or host is None:
+            return True
+        
+        origin = origin.lower()
+        origin_host = urlparse(origin).netloc
+        
+        # OK if origin matches host
+        if origin_host == host:
+            return True
+        
+        # Check CORS headers
+        if self.allow_origin:
+            allow = self.allow_origin == origin
+        elif self.allow_origin_pat:
+            allow = bool(self.allow_origin_pat.match(origin))
+        else:
+            # No CORS headers deny the request
+            allow = False
+        if not allow:
+            self.log.warn("Blocking Cross Origin API request.  Origin: %s, Host: %s",
+                origin, host,
+            )
+        return allow
+
+    def prepare(self):
+        if not self.check_origin():
+            raise web.HTTPError(404)
+        return super(APIHandler, self).prepare()
+
     @property
     def content_security_policy(self):
         csp = '; '.join([
```
