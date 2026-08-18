# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-30 of the vulnerable file.

"""Tornado handlers for the sessions web service."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import json

from tornado import web

from ...base.handlers import IPythonHandler, json_errors
from IPython.utils.jsonutil import date_default
from IPython.html.utils import url_path_join, url_escape
from IPython.kernel.kernelspec import NoSuchKernel


class SessionRootHandler(IPythonHandler):

    @web.authenticated
    @json_errors
    def get(self):
        # Return a list of running sessions
        sm = self.session_manager
        sessions = sm.list_sessions()
        self.finish(json.dumps(sessions, default=date_default))

    @web.authenticated
    @json_errors
    def post(self):
        # Creates a new session
        #(unless a session already exists for the named nb)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,13 +7,13 @@
 
 from tornado import web
 
-from ...base.handlers import IPythonHandler, json_errors
+from ...base.handlers import APIHandler, json_errors
 from IPython.utils.jsonutil import date_default
 from IPython.html.utils import url_path_join, url_escape
 from IPython.kernel.kernelspec import NoSuchKernel
 
 
-class SessionRootHandler(IPythonHandler):
+class SessionRootHandler(APIHandler):
 
     @web.authenticated
     @json_errors
@@ -65,7 +65,7 @@
         self.set_status(201)
         self.finish(json.dumps(model, default=date_default))
 
-class SessionHandler(IPythonHandler):
+class SessionHandler(APIHandler):
 
     SUPPORTED_METHODS = ('GET', 'PATCH', 'DELETE')
 
```
