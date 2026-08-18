# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1687_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1687_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 12-52 of the vulnerable file.

#  the file COPYING, distributed as part of this software.
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------------


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

try:
    from tornado.log import app_log
except ImportError:
    app_log = logging.getLogger()

from IPython.config import Application
from IPython.utils.path import filefind
from IPython.utils.py3compat import string_types
from IPython.html.utils import is_hidden

#-----------------------------------------------------------------------------
# Top-level handlers
#-----------------------------------------------------------------------------
non_alphanum = re.compile(r'[^A-Za-z0-9]')

class AuthenticatedHandler(web.RequestHandler):
    """A RequestHandler with an authenticated user."""
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,10 @@
     from http.client import responses
 except ImportError:
     from httplib import responses
+try:
+    from urllib.parse import urlparse # Py 3
+except ImportError:
+    from urlparse import urlparse # Py 2
 
 from jinja2 import TemplateNotFound
 from tornado import web
@@ -207,6 +211,50 @@
         else:
             origin = self.request.headers.get("Sec-Websocket-Origin", None)
         return origin
+
+    def check_origin_api(self):
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
+        if not self.check_origin_api():
+            raise web.HTTPError(404)
+        return super(IPythonHandler, self).prepare()
 
     #---------------------------------------------------------------
     # template rendering
```
