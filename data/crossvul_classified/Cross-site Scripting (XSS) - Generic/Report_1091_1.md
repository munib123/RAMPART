# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1091_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1091_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-30 of the vulnerable file.

# -*- coding: utf-8 -*-

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, \
    HttpResponseNotFound
from django.shortcuts import redirect
from django.utils.translation import ugettext as _

from zerver.lib.response import json_success, json_error
from zerver.lib.upload import upload_message_image_from_request, get_local_file_path, \
    get_signed_upload_url, check_upload_within_quota
from zerver.models import UserProfile, validate_attachment_request
from django.conf import settings
from sendfile import sendfile
from mimetypes import guess_type

def serve_s3(request: HttpRequest, url_path: str) -> HttpResponse:
    uri = get_signed_upload_url(url_path)
    return redirect(uri)

def serve_local(request: HttpRequest, path_id: str) -> HttpResponse:
    local_path = get_local_file_path(path_id)
    if local_path is None:
        return HttpResponseNotFound('<p>File not found</p>')

    # Here we determine whether a browser should treat the file like
    # an attachment (and thus clicking a link to it should download)
    # or like a link (and thus clicking a link to it should display it
    # in a browser tab).  This is controlled by the
    # Content-Disposition header; `django-sendfile` sends the
    # attachment-style version of that header if and only if the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,7 @@
 
 from zerver.lib.response import json_success, json_error
 from zerver.lib.upload import upload_message_image_from_request, get_local_file_path, \
-    get_signed_upload_url, check_upload_within_quota
+    get_signed_upload_url, check_upload_within_quota, INLINE_MIME_TYPES
 from zerver.models import UserProfile, validate_attachment_request
 from django.conf import settings
 from sendfile import sendfile
@@ -38,13 +38,11 @@
     # consistent format (urlquoted).  For more details on filename*
     # and filename, see the below docs:
     # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition
-    attachment = True
-    file_type = guess_type(local_path)[0]
-    if file_type is not None and (file_type.startswith("image/") or
-                                  file_type == "application/pdf"):
-        attachment = False
+    mimetype, encoding = guess_type(local_path)
+    attachment = mimetype not in INLINE_MIME_TYPES
 
-    return sendfile(request, local_path, attachment=attachment)
+    return sendfile(request, local_path, attachment=attachment,
+                    mimetype=mimetype, encoding=encoding)
 
 def serve_file_backend(request: HttpRequest, user_profile: UserProfile,
                        realm_id_str: str, filename: str) -> HttpResponse:
```
