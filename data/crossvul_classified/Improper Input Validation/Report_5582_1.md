# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 5582_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5582_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 16-53 of the vulnerable file.

    def __call__(self, value, system):

        if 'request' in system:
            request = system['request']

            mime, encoding = mimetypes.guess_type(value['filename'])
            request.response_content_type = mime
            if encoding:
                request.response_encoding = encoding

            f = os.path.join(self.repository_root,
                             value['filename'][0].lower(),
                             value['filename'])

            if not os.path.exists(f):
                dir_ = os.path.join(self.repository_root,
                             value['filename'][0].lower())
                if not os.path.exists(dir_):
                    os.makedirs(dir_, 0750)

                resp = requests.get(value['url'])
                with open(f, 'wb') as rf:
                    rf.write(resp.content)
                return resp.content
            else:
                data = ''
                with open(f, 'rb') as rf:
                    data = ''
                    while True:
                        content = rf.read(2<<16)
                        if not content:
                            break
                        data += content
                return data


def renderer_factory(info):
    return ReleaseFileRenderer(info.settings['pyshop.repository'])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,12 @@
                 if not os.path.exists(dir_):
                     os.makedirs(dir_, 0750)
 
-                resp = requests.get(value['url'])
+                if value['url'].startswith('https://pypi.python.org'):
+                    verify = os.path.join(os.path.dirname(__file__), 'pypi.pem')
+                else:
+                    verify = value['url'].startswith('https:')
+
+                resp = requests.get(value['url'], verify=verify)
                 with open(f, 'wb') as rf:
                     rf.write(resp.content)
                 return resp.content
```
