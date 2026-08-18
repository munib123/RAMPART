# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1644_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1644_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 25-65 of the vulnerable file.


import IPython
from IPython.utils.sysinfo import get_sys_info

from IPython.config import Application
from IPython.utils.path import filefind
from IPython.utils.py3compat import string_types
from IPython.html.utils import is_hidden, url_path_join, url_escape

from IPython.html.services.security import csp_report_uri

#-----------------------------------------------------------------------------
# Top-level handlers
#-----------------------------------------------------------------------------
non_alphanum = re.compile(r'[^A-Za-z0-9]')

sys_info = json.dumps(get_sys_info())

class AuthenticatedHandler(web.RequestHandler):
    """A RequestHandler with an authenticated user."""

    def set_default_headers(self):
        headers = self.settings.get('headers', {})

        if "Content-Security-Policy" not in headers:
            headers["Content-Security-Policy"] = (
                    "frame-ancestors 'self'; "
                    # Make sure the report-uri is relative to the base_url
                    "report-uri " + url_path_join(self.base_url, csp_report_uri) + ";"
            )

        # Allow for overriding headers
        for header_name,value in headers.items() :
            try:
                self.set_header(header_name, value)
            except Exception as e:
                # tornado raise Exception (not a subclass)
                # if method is unsupported (websocket and Access-Control-Allow-Origin
                # for example, so just ignore)
                self.log.debug(e)
    
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,16 +42,24 @@
 
 class AuthenticatedHandler(web.RequestHandler):
     """A RequestHandler with an authenticated user."""
+    
+    @property
+    def content_security_policy(self):
+        """The default Content-Security-Policy header
+        
+        Can be overridden by defining Content-Security-Policy in settings['headers']
+        """
+        return '; '.join([
+            "frame-ancestors 'self'",
+            # Make sure the report-uri is relative to the base_url
+            "report-uri " + url_path_join(self.base_url, csp_report_uri),
+        ])
 
     def set_default_headers(self):
         headers = self.settings.get('headers', {})
 
         if "Content-Security-Policy" not in headers:
-            headers["Content-Security-Policy"] = (
-                    "frame-ancestors 'self'; "
-                    # Make sure the report-uri is relative to the base_url
-                    "report-uri " + url_path_join(self.base_url, csp_report_uri) + ";"
-            )
+            headers["Content-Security-Policy"] = self.content_security_policy
 
         # Allow for overriding headers
         for header_name,value in headers.items() :
@@ -307,7 +315,22 @@
             html = self.render_template('error.html', **ns)
         
         self.write(html)
-        
+
+
+class APIHandler(IPythonHandler):
+    """Base class for API handlers"""
+    
+    @property
+    def content_security_policy(self):
+        csp = '; '.join([
+                super(APIHandler, self).content_security_policy,
+                "default-src 'none'",
+            ])
+        return csp
+    
+    def finish(self, *args, **kwargs):
+        self.set_header('Content-Type', 'application/json')
+        return super(APIHandler, self).finish(*args, **kwargs)
 
 
 class Template404(IPythonHandler):
@@ -370,6 +393,7 @@
         try:
             result = yield gen.maybe_future(method(self, *args, **kwargs))
         except web.HTTPError as e:
+            self.set_header('Content-Type', 'application/json')
             status = e.status_code
             message = e.log_message
             self.log.warn(message)
@@ -377,6 +401,7 @@
             reply = dict(message=message, reason=e.reason)
             self.finish(json.dumps(reply))
         except Exception:
+            self.set_header('Content-Type', 'application/json')
             self.log.error("Unhandled error in API request", exc_info=True)
             status = 500
             message = "Unknown server error"
@@ -399,7 +424,7 @@
 # to minimize subclass changes:
 HTTPError = web.HTTPError
 
-class FileFindHandler(web.StaticFileHandler):
+class FileFindHandler(IPythonHandler, web.StaticFileHandler):
     """subclass of StaticFileHandler for serving files from a search path"""
     
     # cache search results, don't search for files more than once
@@ -453,7 +478,7 @@
         return super(FileFindHandler, self).validate_absolute_path(root, absolute_path)
 
 
-class ApiVersionHandler(IPythonHandler):
+class APIVersionHandler(APIHandler):
 
     @json_errors
     def get(self):
@@ -524,5 +549,5 @@
 
 default_handlers = [
     (r".*/", TrailingSlashHandler),
-    (r"api", ApiVersionHandler)
+    (r"api", APIVersionHandler)
 ]
```
