# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-33 of the vulnerable file.

"""Tornado handlers for kernel specifications."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import glob
import json
import os
pjoin = os.path.join

from tornado import web

from ...base.handlers import IPythonHandler, json_errors
from ...utils import url_path_join

def kernelspec_model(handler, name):
    """Load a KernelSpec by name and return the REST API model"""
    ksm = handler.kernel_spec_manager
    spec = ksm.get_kernel_spec(name)
    d = {'name': name}
    d['spec'] = spec.to_dict()
    d['resources'] = resources = {}
    resource_dir = spec.resource_dir
    for resource in ['kernel.js', 'kernel.css']:
        if os.path.exists(pjoin(resource_dir, resource)):
            resources[resource] = url_path_join(
                handler.base_url,
                'kernelspecs',
                name,
                resource
            )
    for logo_file in glob.glob(pjoin(resource_dir, 'logo-*')):
        fname = os.path.basename(logo_file)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
 
 from tornado import web
 
-from ...base.handlers import IPythonHandler, json_errors
+from ...base.handlers import APIHandler, json_errors
 from ...utils import url_path_join
 
 def kernelspec_model(handler, name):
@@ -40,7 +40,7 @@
         )
     return d
 
-class MainKernelSpecHandler(IPythonHandler):
+class MainKernelSpecHandler(APIHandler):
     SUPPORTED_METHODS = ('GET',)
 
     @web.authenticated
@@ -62,7 +62,7 @@
         self.finish(json.dumps(model))
 
 
-class KernelSpecHandler(IPythonHandler):
+class KernelSpecHandler(APIHandler):
     SUPPORTED_METHODS = ('GET',)
 
     @web.authenticated
```
