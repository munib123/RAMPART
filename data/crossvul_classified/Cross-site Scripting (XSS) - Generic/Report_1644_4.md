# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-36 of the vulnerable file.

"""Tornado handlers for kernels."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import json
import logging
from tornado import gen, web
from tornado.concurrent import Future
from tornado.ioloop import IOLoop

from IPython.utils.jsonutil import date_default
from IPython.utils.py3compat import cast_unicode
from IPython.html.utils import url_path_join, url_escape

from ...base.handlers import IPythonHandler, json_errors
from ...base.zmqhandlers import AuthenticatedZMQStreamHandler, deserialize_binary_message

from IPython.core.release import kernel_protocol_version

class MainKernelHandler(IPythonHandler):

    @web.authenticated
    @json_errors
    def get(self):
        km = self.kernel_manager
        self.finish(json.dumps(km.list_kernels()))

    @web.authenticated
    @json_errors
    def post(self):
        km = self.kernel_manager
        model = self.get_json_body()
        if model is None:
            model = {
                'name': km.default_kernel_name
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,12 +13,12 @@
 from IPython.utils.py3compat import cast_unicode
 from IPython.html.utils import url_path_join, url_escape
 
-from ...base.handlers import IPythonHandler, json_errors
+from ...base.handlers import IPythonHandler, APIHandler, json_errors
 from ...base.zmqhandlers import AuthenticatedZMQStreamHandler, deserialize_binary_message
 
 from IPython.core.release import kernel_protocol_version
 
-class MainKernelHandler(IPythonHandler):
+class MainKernelHandler(APIHandler):
 
     @web.authenticated
     @json_errors
@@ -46,7 +46,7 @@
         self.finish(json.dumps(model))
 
 
-class KernelHandler(IPythonHandler):
+class KernelHandler(APIHandler):
 
     SUPPORTED_METHODS = ('DELETE', 'GET')
 
@@ -67,7 +67,7 @@
         self.finish()
 
 
-class KernelActionHandler(IPythonHandler):
+class KernelActionHandler(APIHandler):
 
     @web.authenticated
     @json_errors
```
