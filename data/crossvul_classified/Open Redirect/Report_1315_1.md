# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1315_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1315_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

# -*- coding: utf-8 -*-
# See https://zulip.readthedocs.io/en/latest/subsystems/thumbnailing.html
import base64
import os
import sys
import urllib
from django.conf import settings
from libthumbor import CryptoURL

ZULIP_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath('__file__'))))
sys.path.append(ZULIP_PATH)

from zthumbor.loaders.helpers import (
    THUMBOR_S3_TYPE, THUMBOR_LOCAL_FILE_TYPE, THUMBOR_EXTERNAL_TYPE
)
from zerver.lib.camo import get_camo_url

def is_thumbor_enabled() -> bool:
    return settings.THUMBOR_URL != ''

def user_uploads_or_external(url: str) -> bool:
    return url.startswith('http') or url.lstrip('/').startswith('user_uploads/')

def get_source_type(url: str) -> str:
    if not url.startswith('/user_uploads/'):
        return THUMBOR_EXTERNAL_TYPE

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 import os
 import sys
 import urllib
+from urllib.parse import urljoin, urlsplit, urlunsplit
 from django.conf import settings
 from libthumbor import CryptoURL
 
@@ -19,7 +20,8 @@
     return settings.THUMBOR_URL != ''
 
 def user_uploads_or_external(url: str) -> bool:
-    return url.startswith('http') or url.lstrip('/').startswith('user_uploads/')
+    u = urlsplit(url)
+    return u.scheme != "" or u.netloc != "" or u.path.startswith("/user_uploads/")
 
 def get_source_type(url: str) -> str:
     if not url.startswith('/user_uploads/'):
@@ -33,16 +35,16 @@
 def generate_thumbnail_url(path: str,
                            size: str='0x0',
                            is_camo_url: bool=False) -> str:
-    if not (path.startswith('https://') or path.startswith('http://')):
-        path = '/' + path
+    path = urljoin("/", path)
+    u = urlsplit(path)
 
     if not is_thumbor_enabled():
-        if path.startswith('http://'):
-            return get_camo_url(path)
-        return path
+        if u.scheme == "" and u.netloc == "":
+            return urlunsplit(u)
+        return get_camo_url(path)
 
-    if not user_uploads_or_external(path):
-        return path
+    if u.scheme == "" and u.netloc == "" and not u.path.startswith("/user_uploads/"):
+        return urlunsplit(u)
 
     source_type = get_source_type(path)
     safe_url = base64.urlsafe_b64encode(path.encode()).decode('utf-8')
```
