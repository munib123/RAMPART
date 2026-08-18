# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1740_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1740_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 23-55 of the vulnerable file.

            raise web.HTTPError(404)
        
        path = path.strip('/')
        if '/' in path:
            _, name = path.rsplit('/', 1)
        else:
            name = path
        
        model = cm.get(path, type='file')
        
        if self.get_argument("download", False):
            self.set_header('Content-Disposition','attachment; filename="%s"' % name)
        
        # get mimetype from filename
        if name.endswith('.ipynb'):
            self.set_header('Content-Type', 'application/json')
        else:
            cur_mime = mimetypes.guess_type(name)[0]
            if cur_mime is not None:
                self.set_header('Content-Type', cur_mime)
        
        if model['format'] == 'base64':
            b64_bytes = model['content'].encode('ascii')
            self.write(base64.decodestring(b64_bytes))
        elif model['format'] == 'json':
            self.write(json.dumps(model['content']))
        else:
            self.write(model['content'])
        self.flush()

default_handlers = [
    (r"/files/(.*)", FilesHandler),
]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,11 @@
             cur_mime = mimetypes.guess_type(name)[0]
             if cur_mime is not None:
                 self.set_header('Content-Type', cur_mime)
+            else:
+                if model['format'] == 'base64':
+                    self.set_header('Content-Type', 'application/octet-stream')
+                else:
+                    self.set_header('Content-Type', 'text/plain')
         
         if model['format'] == 'base64':
             b64_bytes = model['content'].encode('ascii')
```
