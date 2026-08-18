# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1315_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1315_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 1-32 of the vulnerable file.

# Zulip's main markdown implementation.  See docs/subsystems/markdown.md for
# detailed documentation on our markdown syntax.
from typing import (Any, Callable, Dict, Iterable, List, NamedTuple,
                    Optional, Set, Tuple, TypeVar, Union, cast)
from mypy_extensions import TypedDict
from typing.re import Match, Pattern

import markdown
import logging
import traceback
import urllib
import re
import os
import html
import time
import functools
import ujson
import xml.etree.cElementTree as etree
from xml.etree.cElementTree import Element

from collections import deque, defaultdict

import requests

from django.conf import settings
from django.db.models import Q

from markdown.extensions import codehilite, nl2br, tables
from zerver.lib.bugdown import fenced_code
from zerver.lib.bugdown.fenced_code import FENCE_RE
from zerver.lib.camo import get_camo_url
from zerver.lib.emoji import translate_emoticons, emoticon_regex
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 import logging
 import traceback
 import urllib
+import urllib.parse
 import re
 import os
 import html
@@ -553,7 +554,7 @@
         found_imgs = walk_tree(root, lambda e: e if e.tag == "img" else None)
         for img in found_imgs:
             url = img.get("src")
-            if not url.startswith("http://"):
+            if urllib.parse.urlsplit(url).scheme != "http":
                 # Don't rewrite images on our own site (e.g. emoji).
                 continue
             img.set("src", get_camo_url(url))
```
