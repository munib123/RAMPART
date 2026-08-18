# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 407_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `407_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 97-137 of the vulnerable file.

    def get_redirect_target(self, resp):
        """Receives a Response. Returns a redirect URI or ``None``"""
        # Due to the nature of how requests processes redirects this method will
        # be called at least once upon the original response and at least twice
        # on each subsequent redirect response (if any).
        # If a custom mixin is used to handle this logic, it may be advantageous
        # to cache the redirect location onto the response object as a private
        # attribute.
        if resp.is_redirect:
            location = resp.headers['location']
            # Currently the underlying http module on py3 decode headers
            # in latin1, but empirical evidence suggests that latin1 is very
            # rarely used with non-ASCII characters in HTTP headers.
            # It is more likely to get UTF8 header rather than latin1.
            # This causes incorrect handling of UTF8 encoded location headers.
            # To solve this, we re-encode the location in latin1.
            if is_py3:
                location = location.encode('latin1')
            return to_native_string(location, 'utf8')
        return None

    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None, yield_requests=False, **adapter_kwargs):
        """Receives a Response. Returns a generator of Responses or Requests."""

        hist = []  # keep track of history

        url = self.get_redirect_target(resp)
        previous_fragment = urlparse(req.url).fragment
        while url:
            prepared_request = req.copy()

            # Update history and keep track of redirects.
            # resp.history must ignore the original request in this loop
            hist.append(resp)
            resp.history = hist[1:]

            try:
                resp.content  # Consume socket so it can be released
            except (ChunkedEncodingError, ContentDecodingError, RuntimeError):
                resp.raw.read(decode_content=False)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,6 +115,22 @@
             return to_native_string(location, 'utf8')
         return None
 
+    def should_strip_auth(self, old_url, new_url):
+        """Decide whether Authorization header should be removed when redirecting"""
+        old_parsed = urlparse(old_url)
+        new_parsed = urlparse(new_url)
+        if old_parsed.hostname != new_parsed.hostname:
+            return True
+        # Special case: allow http -> https redirect when using the standard
+        # ports. This isn't specified by RFC 7235, but is kept to avoid
+        # breaking backwards compatibility with older versions of requests
+        # that allowed any redirects on the same host.
+        if (old_parsed.scheme == 'http' and old_parsed.port in (80, None)
+                and new_parsed.scheme == 'https' and new_parsed.port in (443, None)):
+            return False
+        # Standard case: root URI must match
+        return old_parsed.port != new_parsed.port or old_parsed.scheme != new_parsed.scheme
+
     def resolve_redirects(self, resp, req, stream=False, timeout=None,
                           verify=True, cert=None, proxies=None, yield_requests=False, **adapter_kwargs):
         """Receives a Response. Returns a generator of Responses or Requests."""
@@ -236,14 +252,10 @@
         headers = prepared_request.headers
         url = prepared_request.url
 
-        if 'Authorization' in headers:
+        if 'Authorization' in headers and self.should_strip_auth(response.request.url, url):
             # If we get redirected to a new host, we should strip out any
             # authentication headers.
-            original_parsed = urlparse(response.request.url)
-            redirect_parsed = urlparse(url)
-
-            if (original_parsed.hostname != redirect_parsed.hostname):
-                del headers['Authorization']
+            del headers['Authorization']
 
         # .netrc might have more auth for us on our new host.
         new_auth = get_netrc_auth(url) if self.trust_env else None
```
