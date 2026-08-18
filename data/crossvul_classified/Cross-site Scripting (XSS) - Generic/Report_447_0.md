# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 447_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `447_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 61-101 of the vulnerable file.

        from nbconvert.exporters.base import get_exporter
    except ImportError as e:
        raise web.HTTPError(500, "Could not import nbconvert: %s" % e)

    try:
        Exporter = get_exporter(format)
    except KeyError:
        # should this be 400?
        raise web.HTTPError(404, u"No exporter for format: %s" % format)

    try:
        return Exporter(**kwargs)
    except Exception as e:
        app_log.exception("Could not construct Exporter: %s", Exporter)
        raise web.HTTPError(500, "Could not construct Exporter: %s" % e)

class NbconvertFileHandler(IPythonHandler):

    SUPPORTED_METHODS = ('GET',)

    @web.authenticated
    def get(self, format, path):

        exporter = get_exporter(format, config=self.config, log=self.log)

        path = path.strip('/')
        # If the notebook relates to a real file (default contents manager),
        # give its path to nbconvert.
        if hasattr(self.contents_manager, '_get_os_path'):
            os_path = self.contents_manager._get_os_path(path)
            ext_resources_dir, basename = os.path.split(os_path)
        else:
            ext_resources_dir = None

        model = self.contents_manager.get(path=path)
        name = model['name']
        if model['type'] != 'notebook':
            # not a notebook, redirect to files
            return FilesRedirectHandler.redirect_to_files(self, path)

        nb = model['content']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,6 +78,13 @@
 
     SUPPORTED_METHODS = ('GET',)
 
+    @property
+    def content_security_policy(self):
+        # In case we're serving HTML/SVG, confine any Javascript to a unique
+        # origin so it can't interact with the notebook server.
+        return super(NbconvertFileHandler, self).content_security_policy + \
+               "; sandbox allow-scripts"
+
     @web.authenticated
     def get(self, format, path):
 
@@ -145,6 +152,13 @@
 class NbconvertPostHandler(IPythonHandler):
     SUPPORTED_METHODS = ('POST',)
 
+    @property
+    def content_security_policy(self):
+        # In case we're serving HTML/SVG, confine any Javascript to a unique
+        # origin so it can't interact with the notebook server.
+        return super(NbconvertPostHandler, self).content_security_policy + \
+               "; sandbox allow-scripts"
+
     @web.authenticated
     def post(self, format):
         exporter = get_exporter(format, config=self.config)
```
