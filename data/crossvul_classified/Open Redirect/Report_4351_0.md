# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 4351_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4351_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 759-801 of the vulnerable file.

            if (absolute_path + os.sep).startswith(root):
                break

        return super(FileFindHandler, self).validate_absolute_path(root, absolute_path)


class APIVersionHandler(APIHandler):

    def get(self):
        # not authenticated, so give as few info as possible
        self.finish(json.dumps({"version": jupyter_server.__version__}))


class TrailingSlashHandler(web.RequestHandler):
    """Simple redirect handler that strips trailing slashes

    This should be the first, highest priority handler.
    """

    def get(self):
        uri = self.request.path.rstrip("/")
        if uri:
            self.redirect('?'.join((uri, self.request.query)))

    post = put = get


class MainHandler(JupyterHandler):
    """Simple handler for base_url."""

    def get(self):
        html = self.render_template("main.html")
        self.write(html)

    post = put = get


class FilesRedirectHandler(JupyterHandler):
    """Handler for redirecting relative URLs to the /files/ handler"""

    @staticmethod
    def redirect_to_files(self, path):
        """make redirect logic a reusable static method
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -776,9 +776,12 @@
     """
 
     def get(self):
-        uri = self.request.path.rstrip("/")
-        if uri:
-            self.redirect('?'.join((uri, self.request.query)))
+        path, *rest = self.request.uri.partition("?")
+        # trim trailing *and* leading /
+        # to avoid misinterpreting repeated '//'
+        path = "/" + path.strip("/")
+        new_uri = "".join([path, *rest])
+        self.redirect(new_uri)
 
     post = put = get
 
```
