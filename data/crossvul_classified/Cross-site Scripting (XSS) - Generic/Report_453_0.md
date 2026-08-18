# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 453_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `453_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-31 of the vulnerable file.

"""A cleanup tool for HTML.

Removes unwanted tags and content.  See the `Cleaner` class for
details.
"""

import re
import copy
try:
    from urlparse import urlsplit
except ImportError:
    # Python 3
    from urllib.parse import urlsplit
from lxml import etree
from lxml.html import defs
from lxml.html import fromstring, XHTML_NAMESPACE
from lxml.html import xhtml_to_html, _transform_result

try:
    unichr
except NameError:
    # Python 3
    unichr = chr
try:
    unicode
except NameError:
    # Python 3
    unicode = str
try:
    bytes
except NameError:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,9 +8,10 @@
 import copy
 try:
     from urlparse import urlsplit
+    from urllib import unquote_plus
 except ImportError:
     # Python 3
-    from urllib.parse import urlsplit
+    from urllib.parse import urlsplit, unquote_plus
 from lxml import etree
 from lxml.html import defs
 from lxml.html import fromstring, XHTML_NAMESPACE
@@ -482,7 +483,7 @@
 
     def _remove_javascript_link(self, link):
         # links like "j a v a s c r i p t:" might be interpreted in IE
-        new = _substitute_whitespace('', link)
+        new = _substitute_whitespace('', unquote_plus(link))
         if _is_javascript_scheme(new):
             # FIXME: should this be None to delete?
             return ''
```
