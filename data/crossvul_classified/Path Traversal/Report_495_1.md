# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 495_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `495_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 26-66 of the vulnerable file.

    curl --noproxy localhost -iv http://localhost:18888/file/example.txt

Fetch gzipped example file 'example.txt'

    curl --compressed -H "Accept-Encoding: gzip" --noproxy localhost -iv http://localhost:18888/file/example.txt

Delete example file 'example.txt'

    curl --noproxy localhost -iv -X DELETE http://localhost:18888/file/example.txt

"""
import os
import json
import glob
import re
import urlparse

import twisted.web.static
from twisted.web import http

import file

MANY_SLASHES_PATTERN = r'[\/]+'
MANY_SLASHES_REGEX = re.compile(MANY_SLASHES_PATTERN)

#: default path from which files will be served
DEFAULT_ROOT_PATH = os.path.abspath(os.path.dirname(__file__))

#: CORS - HTTP headers the client may use
CORS_ALLOWED_CLIENT_HEADERS = [
	'Content-Type',
]

#: CORS - HTTP methods the client may use
CORS_ALLOWED_METHODS_DEFAULT = ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS']

#: CORS - default origin header value
CORS_DEFAULT_ALLOW_ORIGIN = '*'

#: CORS - HTTP headers the server will send as part of OPTIONS response
CORS_DEFAULT = {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,10 +43,8 @@
 import twisted.web.static
 from twisted.web import http
 
+from utilities import MANY_SLASHES_REGEX
 import file
-
-MANY_SLASHES_PATTERN = r'[\/]+'
-MANY_SLASHES_REGEX = re.compile(MANY_SLASHES_PATTERN)
 
 #: default path from which files will be served
 DEFAULT_ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
```
