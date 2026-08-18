# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-30 of the vulnerable file.

"""Tornado handlers for cluster web service."""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import json

from tornado import web

from ...base.handlers import IPythonHandler

#-----------------------------------------------------------------------------
# Cluster handlers
#-----------------------------------------------------------------------------


class MainClusterHandler(IPythonHandler):

    @web.authenticated
    def get(self):
        self.finish(json.dumps(self.cluster_manager.list_profiles()))


class ClusterProfileHandler(IPythonHandler):

    @web.authenticated
    def get(self, profile):
        self.finish(json.dumps(self.cluster_manager.profile_info(profile)))


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,28 +7,28 @@
 
 from tornado import web
 
-from ...base.handlers import IPythonHandler
+from ...base.handlers import APIHandler
 
 #-----------------------------------------------------------------------------
 # Cluster handlers
 #-----------------------------------------------------------------------------
 
 
-class MainClusterHandler(IPythonHandler):
+class MainClusterHandler(APIHandler):
 
     @web.authenticated
     def get(self):
         self.finish(json.dumps(self.cluster_manager.list_profiles()))
 
 
-class ClusterProfileHandler(IPythonHandler):
+class ClusterProfileHandler(APIHandler):
 
     @web.authenticated
     def get(self, profile):
         self.finish(json.dumps(self.cluster_manager.profile_info(profile)))
 
 
-class ClusterActionHandler(IPythonHandler):
+class ClusterActionHandler(APIHandler):
 
     @web.authenticated
     def post(self, profile, action):
```
