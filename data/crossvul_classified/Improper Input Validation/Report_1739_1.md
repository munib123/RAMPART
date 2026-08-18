# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1739_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1739_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 260-300 of the vulnerable file.

                    )

            model['format'] = 'json'

        return model

    def _file_model(self, path, content=True, format=None):
        """Build a model for a file

        if content is requested, include the file contents.

        format:
          If 'text', the contents will be decoded as UTF-8.
          If 'base64', the raw bytes contents will be encoded as base64.
          If not specified, try to decode as UTF-8, and fall back to base64
        """
        model = self._base_model(path)
        model['type'] = 'file'

        os_path = self._get_os_path(path)

        if content:
            content, format = self._read_file(os_path, format)
            default_mime = {
                'text': 'text/plain',
                'base64': 'application/octet-stream'
            }[format]

            model.update(
                content=content,
                format=format,
                mimetype=mimetypes.guess_type(os_path)[0] or default_mime,
            )

        return model

    def _notebook_model(self, path, content=True):
        """Build a notebook model

        if content is requested, the notebook content will be populated
        as a JSON structure (not double-serialized)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -277,18 +277,20 @@
         model['type'] = 'file'
 
         os_path = self._get_os_path(path)
+        model['mimetype'] = mimetypes.guess_type(os_path)[0]
 
         if content:
             content, format = self._read_file(os_path, format)
-            default_mime = {
-                'text': 'text/plain',
-                'base64': 'application/octet-stream'
-            }[format]
+            if model['mimetype'] is None:
+                default_mime = {
+                    'text': 'text/plain',
+                    'base64': 'application/octet-stream'
+                }[format]
+                model['mimetype'] = default_mime
 
             model.update(
                 content=content,
                 format=format,
-                mimetype=mimetypes.guess_type(os_path)[0] or default_mime,
             )
 
         return model
```
