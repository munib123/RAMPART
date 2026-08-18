# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 753_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `753_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 22-62 of the vulnerable file.

class LoginHandler(IPythonHandler):
    """The basic tornado login handler

    authenticates with a hashed password from the configuration.
    """
    def _render(self, message=None):
        self.write(self.render_template('login.html',
                next=url_escape(self.get_argument('next', default=self.base_url)),
                message=message,
        ))

    def _redirect_safe(self, url, default=None):
        """Redirect if url is on our PATH

        Full-domain redirects are allowed if they pass our CORS origin checks.

        Otherwise use default (self.base_url if unspecified).
        """
        if default is None:
            default = self.base_url
        if not url.startswith(self.base_url):
            # require that next_url be absolute path within our path
            allow = False
            # OR pass our cross-origin check
            if '://' in url:
                # if full URL, run our cross-origin check:
                parsed = urlparse(url.lower())
                origin = '%s://%s' % (parsed.scheme, parsed.netloc)
                if self.allow_origin:
                    allow = self.allow_origin == origin
                elif self.allow_origin_pat:
                    allow = bool(self.allow_origin_pat.match(origin))
            if not allow:
                # not allowed, use default
                self.log.warning("Not allowing login redirect to %r" % url)
                url = default
        self.redirect(url)

    def get(self):
        if self.current_user:
            next_url = self.get_argument('next', default=self.base_url)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,14 +39,15 @@
         """
         if default is None:
             default = self.base_url
-        if not url.startswith(self.base_url):
+        parsed = urlparse(url)
+        if parsed.netloc or not (parsed.path + '/').startswith(self.base_url):
             # require that next_url be absolute path within our path
             allow = False
             # OR pass our cross-origin check
-            if '://' in url:
+            if parsed.netloc:
                 # if full URL, run our cross-origin check:
-                parsed = urlparse(url.lower())
                 origin = '%s://%s' % (parsed.scheme, parsed.netloc)
+                origin = origin.lower()
                 if self.allow_origin:
                     allow = self.allow_origin == origin
                 elif self.allow_origin_pat:
```
