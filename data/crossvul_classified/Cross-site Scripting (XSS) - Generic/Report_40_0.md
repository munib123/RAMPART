# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 40_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `40_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 7-47 of the vulnerable file.

# qutebrowser is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# qutebrowser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with qutebrowser.  If not, see <http://www.gnu.org/licenses/>.

"""Backend-independent qute://* code.

Module attributes:
    pyeval_output: The output of the last :pyeval command.
    _HANDLERS: The handlers registered via decorators.
"""

import json
import os
import time
import textwrap
import mimetypes
import urllib
import collections

import pkg_resources
import sip
from PyQt5.QtCore import QUrlQuery, QUrl

import qutebrowser
from qutebrowser.config import config, configdata, configexc, configdiff
from qutebrowser.utils import (version, utils, jinja, log, message, docutils,
                               objreg, urlutils)
from qutebrowser.misc import objects


pyeval_output = ":pyeval was never called"
spawn_output = ":spawn was never called"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,7 @@
     _HANDLERS: The handlers registered via decorators.
 """
 
+import html
 import json
 import os
 import time
@@ -241,8 +242,9 @@
         end_time = start_time - 24*60*60
         entries = hist.entries_between(end_time, start_time)
 
-    return [{"url": e.url, "title": e.title or e.url, "time": e.atime}
-            for e in entries]
+    return [{"url": html.escape(e.url),
+             "title": html.escape(e.title) or html.escape(e.url),
+             "time": e.atime} for e in entries]
 
 
 @add_handler('history')
```
