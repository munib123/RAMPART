# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-25 of the vulnerable file.

import json

from tornado import web

from ...base.handlers import IPythonHandler, json_errors

class NbconvertRootHandler(IPythonHandler):
    SUPPORTED_METHODS = ('GET',)

    @web.authenticated
    @json_errors
    def get(self):
        try:
            from IPython.nbconvert.exporters.export import exporter_map
        except ImportError as e:
            raise web.HTTPError(500, "Could not import nbconvert: %s" % e)
        res = {}
        for format, exporter in exporter_map.items():
            res[format] = info = {}
            info['output_mimetype'] = exporter.output_mimetype

        self.finish(json.dumps(res))

default_handlers = [
    (r"/api/nbconvert", NbconvertRootHandler),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,9 @@
 
 from tornado import web
 
-from ...base.handlers import IPythonHandler, json_errors
+from ...base.handlers import APIHandler, json_errors
 
-class NbconvertRootHandler(IPythonHandler):
+class NbconvertRootHandler(APIHandler):
     SUPPORTED_METHODS = ('GET',)
 
     @web.authenticated
```
