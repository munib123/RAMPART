# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 4208_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4208_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-35 of the vulnerable file.

# -*- coding: iso-8859-1 -*-
"""
    MoinMoin - site-wide configuration defaults (NOT per single wiki!)

    @copyright: 2005-2006 MoinMoin:ThomasWaldmann
    @license: GNU GPL, see COPYING for details.
"""
import re
from MoinMoin import version

# unicode: set the char types (upper, lower, digits, spaces)
from MoinMoin.util.chartypes import *

# List of image types browser do support regulary
browser_supported_images = ('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', )

# Parser to use mimetype text
parser_text_mimetype = ('plain', 'csv', 'rst', 'docbook', 'latex', 'tex', 'html', 'css',
                       'xml', 'python', 'perl', 'php', 'ruby', 'javascript',
                       'cplusplus', 'java', 'pascal', 'diff', 'gettext', 'xslt', 'creole', )

# When creating files, we use e.g. 0666 & config.umask for the mode:
umask = 0770

# list of acceptable password hashing schemes for cfg.password_scheme,
# here we only give reasonably good schemes, which is passlib (if we
# have passlib) and ssha (if we only have builtin stuff):
password_schemes_configurable = ['{PASSLIB}', '{SSHA}', ]

# ordered list of supported password hashing schemes, best (passlib) should be
# first, best builtin one should be second. this is what we support if we
# encounter it in user profiles:
password_schemes_supported = password_schemes_configurable + ['{SHA}', '{APR1}', '{MD5}', '{DES}', ]

# Default value for the static stuff URL prefix (css, img, js).
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,7 @@
 from MoinMoin.util.chartypes import *
 
 # List of image types browser do support regulary
-browser_supported_images = ('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', )
+browser_supported_images = ('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', 'svg+xml')
 
 # Parser to use mimetype text
 parser_text_mimetype = ('plain', 'csv', 'rst', 'docbook', 'latex', 'tex', 'html', 'css',
```
