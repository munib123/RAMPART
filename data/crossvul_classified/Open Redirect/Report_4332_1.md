# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 4332_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4332_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 837-877 of the vulnerable file.

        """check if the file should be served (raises 404, 403, etc.)"""
        if absolute_path == '':
            raise web.HTTPError(404)
        
        for root in self.root:
            if (absolute_path + os.sep).startswith(root):
                break
        
        return super(FileFindHandler, self).validate_absolute_path(root, absolute_path)


class APIVersionHandler(APIHandler):

    def get(self):
        # not authenticated, so give as few info as possible
        self.finish(json.dumps({"version":notebook.__version__}))


class TrailingSlashHandler(web.RequestHandler):
    """Simple redirect handler that strips trailing slashes
    
    This should be the first, highest priority handler.
    """
    
    def get(self):
        self.redirect(self.request.uri.rstrip('/'))
    
    post = put = get


class FilesRedirectHandler(IPythonHandler):
    """Handler for redirecting relative URLs to the /files/ handler"""
    
    @staticmethod
    def redirect_to_files(self, path):
        """make redirect logic a reusable static method
        
        so it can be called from other handlers.
        """
        cm = self.contents_manager
        if cm.dir_exists(path):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -854,13 +854,18 @@
 
 class TrailingSlashHandler(web.RequestHandler):
     """Simple redirect handler that strips trailing slashes
-    
+
     This should be the first, highest priority handler.
     """
-    
+
     def get(self):
-        self.redirect(self.request.uri.rstrip('/'))
-    
+        path, *rest = self.request.uri.partition("?")
+        # trim trailing *and* leading /
+        # to avoid misinterpreting repeated '//'
+        path = "/" + path.strip("/")
+        new_uri = "".join([path, *rest])
+        self.redirect(new_uri)
+
     post = put = get
 
 
@@ -911,6 +916,7 @@
         url = sep.join([self._url, self.request.query])
         self.redirect(url, permanent=self._permanent)
 
+
 class PrometheusMetricsHandler(IPythonHandler):
     """
     Return prometheus metrics for this notebook server
```
