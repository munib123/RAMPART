# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-23 of the vulnerable file.

"""Tornado handlers for security logging."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

from tornado import gen, web

from ...base.handlers import IPythonHandler, json_errors
from . import csp_report_uri

class CSPReportHandler(IPythonHandler):
    '''Accepts a content security policy violation report'''
    @web.authenticated
    @json_errors
    def post(self):
        '''Log a content security policy violation report'''
        csp_report = self.get_json_body()
        self.log.warn("Content security violation: %s",
                      self.request.body.decode('utf8', 'replace'))

default_handlers = [
    (csp_report_uri, CSPReportHandler)
]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,10 +5,10 @@
 
 from tornado import gen, web
 
-from ...base.handlers import IPythonHandler, json_errors
+from ...base.handlers import APIHandler, json_errors
 from . import csp_report_uri
 
-class CSPReportHandler(IPythonHandler):
+class CSPReportHandler(APIHandler):
     '''Accepts a content security policy violation report'''
     @web.authenticated
     @json_errors
```
