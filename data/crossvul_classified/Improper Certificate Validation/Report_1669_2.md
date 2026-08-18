# CrossVul Fix Pair: Improper Certificate Validation in python
**Pair ID:** 1669_2
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1669_2`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```python
Lines 67-108 of the vulnerable file.

        if default_locale:
            default_locale = default_locale.lower().replace('_', '-')
        else:
            default_locale = 'en-us'

        # Headers
        self.headers = {'Accept': 'application/json',
                        'Accept-Language': default_locale,
                        'Content-Type': 'application/json'}

        # Server Wrapper
        if server_wrapper:
            self.server_wrapper = server_wrapper
        else:
            self.server_wrapper = HTTPSServerWrapper(self)

        # SSL validation settings
        self.verify_ssl = verify_ssl
        self.ca_path = ca_path

    def DELETE(self, path, body=None, log_request_body=True):
        return self._request('DELETE', path, body=body, log_request_body=log_request_body)

    def GET(self, path, queries=()):
        return self._request('GET', path, queries)

    def HEAD(self, path):
        return self._request('HEAD', path)

    def POST(self, path, body=None, ensure_encoding=True, log_request_body=True):
        return self._request('POST', path, body=body, ensure_encoding=ensure_encoding,
                             log_request_body=log_request_body)

    def PUT(self, path, body, ensure_encoding=True, log_request_body=True):
        return self._request('PUT', path, body=body, ensure_encoding=ensure_encoding,
                             log_request_body=log_request_body)

    # protected request utilities ---------------------------------------------

    def _request(self, method, path, queries=(), body=None, ensure_encoding=True,
                 log_request_body=True):
        """
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,27 +84,29 @@
         self.verify_ssl = verify_ssl
         self.ca_path = ca_path
 
-    def DELETE(self, path, body=None, log_request_body=True):
-        return self._request('DELETE', path, body=body, log_request_body=log_request_body)
-
-    def GET(self, path, queries=()):
-        return self._request('GET', path, queries)
-
-    def HEAD(self, path):
-        return self._request('HEAD', path)
-
-    def POST(self, path, body=None, ensure_encoding=True, log_request_body=True):
+    def DELETE(self, path, body=None, log_request_body=True, ignore_prefix=False):
+        return self._request('DELETE', path, body=body, log_request_body=log_request_body,
+                             ignore_prefix=ignore_prefix)
+
+    def GET(self, path, queries=(), ignore_prefix=False):
+        return self._request('GET', path, queries, ignore_prefix=ignore_prefix)
+
+    def HEAD(self, path, ignore_prefix=False):
+        return self._request('HEAD', path, ignore_prefix=ignore_prefix)
+
+    def POST(self, path, body=None, ensure_encoding=True, log_request_body=True,
+             ignore_prefix=False):
         return self._request('POST', path, body=body, ensure_encoding=ensure_encoding,
-                             log_request_body=log_request_body)
-
-    def PUT(self, path, body, ensure_encoding=True, log_request_body=True):
+                             log_request_body=log_request_body, ignore_prefix=ignore_prefix)
+
+    def PUT(self, path, body, ensure_encoding=True, log_request_body=True, ignore_prefix=False):
         return self._request('PUT', path, body=body, ensure_encoding=ensure_encoding,
-                             log_request_body=log_request_body)
+                             log_request_body=log_request_body, ignore_prefix=ignore_prefix)
 
     # protected request utilities ---------------------------------------------
 
     def _request(self, method, path, queries=(), body=None, ensure_encoding=True,
-                 log_request_body=True):
+                 log_request_body=True, ignore_prefix=False):
         """
         make a HTTP request to the pulp server and return the response
 
@@ -130,6 +132,9 @@
         :param log_request_body: Toggle logging of the request body, defaults to true
         :type log_request_body: bool
 
+        :param ignore_prefix: when building the url, disregard the self.path_prefix
+        :type  ignore_prefix: bool
+
         :return:    Response object
         :rtype:     pulp.bindings.responses.Response
 
@@ -137,7 +142,7 @@
                     (depending on response codes) in case of unsuccessful
                     request
         """
-        url = self._build_url(path, queries)
+        url = self._build_url(path, queries, ignore_prefix)
         if ensure_encoding:
             body = self._process_body(body)
         if not isinstance(body, (NoneType, basestring)):
@@ -201,7 +206,7 @@
         else:
             raise code_class_mappings[response_code](response_body)
 
-    def _build_url(self, path, queries=()):
+    def _build_url(self, path, queries, ignore_prefix):
         """
         Takes a relative path and query parameters, combines them with the
         base path, and returns the result. Handles utf-8 encoding as necessary.
@@ -217,13 +222,15 @@
                         in either case representing key-value pairs to be used
                         as query parameters on the URL.
         :type  queries: mapping object or sequence of 2-element tuples
+        :param ignore_prefix: when building the url, disregard the self.path_prefix
+        :type  ignore_prefix: bool
 
         :return:    path that is a composite of self.path_prefix, path, and
                     queries. May be relative or absolute depending on the nature
                     of self.path_prefix
         """
         # build the request url from the path and queries dict or tuple
-        if not path.startswith(self.path_prefix):
+        if not path.startswith(self.path_prefix) and not ignore_prefix:
             if path.startswith('/'):
                 path = path[1:]
             path = '/'.join((self.path_prefix, path))
```
