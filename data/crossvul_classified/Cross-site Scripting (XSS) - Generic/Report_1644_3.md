# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-34 of the vulnerable file.

"""Tornado handlers for the contents web service."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import json

from tornado import gen, web

from IPython.html.utils import url_path_join, url_escape
from IPython.utils.jsonutil import date_default

from IPython.html.base.handlers import (
    IPythonHandler, json_errors, path_regex,
)


def sort_key(model):
    """key function for case-insensitive sort by name and type"""
    iname = model['name'].lower()
    type_key = {
        'directory' : '0',
        'notebook'  : '1',
        'file'      : '2',
    }.get(model['type'], '9')
    return u'%s%s' % (type_key, iname)


def validate_model(model, expect_content):
    """
    Validate a model returned by a ContentsManager method.

    If expect_content is True, then we expect non-null entries for 'content'
    and 'format'.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
 from IPython.utils.jsonutil import date_default
 
 from IPython.html.base.handlers import (
-    IPythonHandler, json_errors, path_regex,
+    IPythonHandler, APIHandler, json_errors, path_regex,
 )
 
 
@@ -75,7 +75,7 @@
             )
 
 
-class ContentsHandler(IPythonHandler):
+class ContentsHandler(APIHandler):
 
     SUPPORTED_METHODS = (u'GET', u'PUT', u'PATCH', u'POST', u'DELETE')
 
@@ -257,7 +257,7 @@
         self.finish()
 
 
-class CheckpointsHandler(IPythonHandler):
+class CheckpointsHandler(APIHandler):
 
     SUPPORTED_METHODS = ('GET', 'POST')
 
@@ -286,7 +286,7 @@
         self.finish(data)
 
 
-class ModifyCheckpointsHandler(IPythonHandler):
+class ModifyCheckpointsHandler(APIHandler):
 
     SUPPORTED_METHODS = ('POST', 'DELETE')
 
```
