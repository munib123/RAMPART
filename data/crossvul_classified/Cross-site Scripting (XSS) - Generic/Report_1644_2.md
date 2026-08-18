# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-32 of the vulnerable file.

"""Tornado handlers for frontend config storage."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.
import json
import os
import io
import errno
from tornado import web

from IPython.utils.py3compat import PY3
from ...base.handlers import IPythonHandler, json_errors

class ConfigHandler(IPythonHandler):
    SUPPORTED_METHODS = ('GET', 'PUT', 'PATCH')

    @web.authenticated
    @json_errors
    def get(self, section_name):
        self.set_header("Content-Type", 'application/json')
        self.finish(json.dumps(self.config_manager.get(section_name)))

    @web.authenticated
    @json_errors
    def put(self, section_name):
        data = self.get_json_body()  # Will raise 400 if content is not valid JSON
        self.config_manager.set(section_name, data)
        self.set_status(204)

    @web.authenticated
    @json_errors
    def patch(self, section_name):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,9 +9,9 @@
 from tornado import web
 
 from IPython.utils.py3compat import PY3
-from ...base.handlers import IPythonHandler, json_errors
+from ...base.handlers import APIHandler, json_errors
 
-class ConfigHandler(IPythonHandler):
+class ConfigHandler(APIHandler):
     SUPPORTED_METHODS = ('GET', 'PUT', 'PATCH')
 
     @web.authenticated
```
