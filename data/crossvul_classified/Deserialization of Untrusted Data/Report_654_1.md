# CrossVul Fix Pair: Deserialization of Untrusted Data in python
**Pair ID:** 654_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `654_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```python
Lines 9-49 of the vulnerable file.

import random
import shutil
import sys
import zipfile
from json import load as load_json_file
from threading import Lock

from calibre import as_unicode
from calibre.customize.ui import available_input_formats
from calibre.db.view import sanitize_sort_field_name
from calibre.srv.ajax import search_result
from calibre.srv.errors import (
    BookNotFound, HTTPBadRequest, HTTPForbidden, HTTPNotFound
)
from calibre.srv.metadata import (
    book_as_json, categories_as_json, categories_settings, icon_map
)
from calibre.srv.routes import endpoint, json
from calibre.srv.utils import get_library_data, get_use_roman
from calibre.utils.config import prefs, tweaks
from calibre.utils.icu import sort_key
from calibre.utils.localization import get_lang
from calibre.utils.search_query_parser import ParseException

POSTABLE = frozenset({'GET', 'POST', 'HEAD'})


@endpoint('', auth_required=False)
def index(ctx, rd):
    return lopen(P('content-server/index-generated.html'), 'rb')


@endpoint('/calibre.appcache', auth_required=False, cache_control='no-cache')
def appcache(ctx, rd):
    return lopen(P('content-server/calibre.appcache'), 'rb')


@endpoint('/robots.txt', auth_required=False)
def robots(ctx, rd):
    return b'User-agent: *\nDisallow: /'

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 from calibre.srv.routes import endpoint, json
 from calibre.srv.utils import get_library_data, get_use_roman
 from calibre.utils.config import prefs, tweaks
-from calibre.utils.icu import sort_key
+from calibre.utils.icu import sort_key, numeric_sort_key
 from calibre.utils.localization import get_lang
 from calibre.utils.search_query_parser import ParseException
 
@@ -393,4 +393,4 @@
     Optional: ?library_id=<default library>
     '''
     db, library_id = get_library_data(ctx, rd)[:2]
-    return tuple(db.all_field_names(field))
+    return tuple(sorted(db.all_field_names(field), key=numeric_sort_key))
```
