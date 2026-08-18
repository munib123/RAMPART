# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 2196_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2196_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

import socketio
import traceback

from ajenti.http import HttpHandler
from ajenti.api import BasePlugin, plugin, persistent, rootcontext
from ajenti.api.http import HttpPlugin, SocketPlugin
from ajenti.plugins import manager
from ajenti.profiler import *


class SocketIORouteHandler (HttpHandler):
    def __init__(self):
        self.namespaces = {}
        for cls in SocketPlugin.get_classes():
            self.namespaces[cls.name] = cls

    def handle(self, context):
        return str(socketio.socketio_manage(context.env, self.namespaces, context))


class InvalidRouteHandler (HttpHandler):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+import cgi
 import socketio
 import traceback
 
@@ -90,4 +91,4 @@
                 </pre>
             </body>
         </html>
-        """ % stack
+        """ % cgi.escape(stack)
```
