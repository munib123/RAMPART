# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in python
**Pair ID:** 1121_5
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1121_5`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```python
Lines 4-44 of the vulnerable file.

# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Utility functions
"""

import calendar
import errno
import logging
import os
import re
import stat
import time

logger = logging.getLogger("waitress")
queue_logger = logging.getLogger("waitress.queue")


def find_double_newline(s):
    """Returns the position just after a double newline in the given string."""
    pos = s.find(b"\r\n\r\n")

    if pos >= 0:
        pos += 4

    return pos


def concat(*args):
    return "".join(args)


def join(seq, field=" "):
    return field.join(seq)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,8 @@
 import stat
 import time
 
+from .rfc7230 import OBS_TEXT, VCHAR
+
 logger = logging.getLogger("waitress")
 queue_logger = logging.getLogger("waitress.queue")
 
@@ -63,6 +65,7 @@
 long_day_reg = group(join(long_days, "|"))
 
 daymap = {}
+
 for i in range(7):
     daymap[short_days[i]] = i
     daymap[long_days[i]] = i
@@ -85,6 +88,7 @@
 ]
 
 monmap = {}
+
 for i in range(12):
     monmap[months[i]] = i + 1
 
@@ -113,6 +117,7 @@
 
 def unpack_rfc822(m):
     g = m.group
+
     return (
         int(g(4)),  # year
         monmap[g(3)],  # month
@@ -142,8 +147,10 @@
 def unpack_rfc850(m):
     g = m.group
     yr = g(4)
+
     if len(yr) == 2:
         yr = "19" + yr
+
     return (
         int(yr),  # year
         monmap[g(3)],  # month
@@ -180,6 +187,7 @@
 
 def build_http_date(when):
     year, month, day, hh, mm, ss, wd, y, z = time.gmtime(when)
+
     return "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
         weekdayname[wd],
         day,
@@ -194,28 +202,31 @@
 def parse_http_date(d):
     d = d.lower()
     m = rfc850_reg.match(d)
+
     if m and m.end() == len(d):
         retval = int(calendar.timegm(unpack_rfc850(m)))
     else:
         m = rfc822_reg.match(d)
+
         if m and m.end() == len(d):
             retval = int(calendar.timegm(unpack_rfc822(m)))
         else:
             return 0
+
     return retval
 
 
 # RFC 5234 Appendix B.1 "Core Rules":
 # VCHAR         =  %x21-7E
 #                  ; visible (printing) characters
-vchar_re = "\x21-\x7e"
+vchar_re = VCHAR
 
 # RFC 7230 Section 3.2.6 "Field Value Components":
 # quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 # qdtext        = HTAB / SP /%x21 / %x23-5B / %x5D-7E / obs-text
 # obs-text      = %x80-FF
 # quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
-obs_text_re = "\x80-\xff"
+obs_text_re = OBS_TEXT
 
 # The '\\' between \x5b and \x5d is needed to escape \x5d (']')
 qdtext_re = "[\t \x21\x23-\x5b\\\x5d-\x7e" + obs_text_re + "]"
```
