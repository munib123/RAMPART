# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1091_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1091_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

from typing import Dict, Optional, Tuple

from django.utils.translation import ugettext as _
from django.conf import settings
from django.core.files import File
from django.http import HttpRequest
from django.db.models import Sum
from jinja2 import Markup as mark_safe
import unicodedata

from zerver.lib.avatar_hash import user_avatar_path
from zerver.lib.exceptions import JsonableError, ErrorCode

from boto.s3.bucket import Bucket
from boto.s3.key import Key
from boto.s3.connection import S3Connection
from mimetypes import guess_type, guess_extension

from zerver.models import get_user_profile_by_id
from zerver.models import Attachment
from zerver.models import Realm, RealmEmoji, UserProfile, Message
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-from typing import Dict, Optional, Tuple
+from typing import Optional, Tuple
 
 from django.utils.translation import ugettext as _
 from django.conf import settings
@@ -40,6 +40,17 @@
 # network cost of very large emoji images.
 MAX_EMOJI_GIF_SIZE = 128
 MAX_EMOJI_GIF_FILE_SIZE_BYTES = 128 * 1024 * 1024  # 128 kb
+
+INLINE_MIME_TYPES = [
+    "application/pdf",
+    "image/gif",
+    "image/jpeg",
+    "image/png",
+    "image/webp",
+    # To avoid cross-site scripting attacks, DO NOT add types such
+    # as application/xhtml+xml, application/x-shockwave-flash,
+    # image/svg+xml, text/html, or text/xml.
+]
 
 # Performance Note:
 #
@@ -267,10 +278,11 @@
     key.set_metadata("user_profile_id", str(user_profile.id))
     key.set_metadata("realm_id", str(user_profile.realm_id))
 
+    headers = {}
     if content_type is not None:
-        headers = {'Content-Type': content_type}  # type: Optional[Dict[str, str]]
-    else:
-        headers = None
+        headers["Content-Type"] = content_type
+    if content_type not in INLINE_MIME_TYPES:
+        headers["Content-Disposition"] = "attachment"
 
     key.set_contents_from_string(contents, headers=headers)  # type: ignore # https://github.com/python/typeshed/issues/1552
 
```
