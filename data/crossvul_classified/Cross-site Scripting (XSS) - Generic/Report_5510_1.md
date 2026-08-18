# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5510_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5510_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-33 of the vulnerable file.

from __future__ import absolute_import, division, unicode_literals
from six import text_type

import re

from ..constants import voidElements, booleanAttributes, spaceCharacters
from ..constants import rcdataElements, entities, xmlEntities
from .. import utils
from xml.sax.saxutils import escape

spaceCharacters = "".join(spaceCharacters)

quoteAttributeSpec = re.compile("[" + spaceCharacters + "\"'=<>`]")

try:
    from codecs import register_error, xmlcharrefreplace_errors
except ImportError:
    unicode_encode_errors = "strict"
else:
    unicode_encode_errors = "htmlentityreplace"

    encode_entity_map = {}
    is_ucs4 = len("\U0010FFFF") == 1
    for k, v in list(entities.items()):
        # skip multi-character entities
        if ((is_ucs4 and len(v) > 1) or
                (not is_ucs4 and len(v) > 2)):
            continue
        if v != "&":
            if len(v) == 2:
                v = utils.surrogatePairToCodepoint(v)
            else:
                v = ord(v)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,16 @@
 
 spaceCharacters = "".join(spaceCharacters)
 
-quoteAttributeSpec = re.compile("[" + spaceCharacters + "\"'=<>`]")
+quoteAttributeSpecChars = spaceCharacters + "\"'=<>`"
+quoteAttributeSpec = re.compile("[" + quoteAttributeSpecChars + "]")
+quoteAttributeLegacy = re.compile("[" + quoteAttributeSpecChars +
+                                  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n"
+                                  "\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15"
+                                  "\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
+                                  "\x20\x2f\x60\xa0\u1680\u180e\u180f\u2000"
+                                  "\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
+                                  "\u2008\u2009\u200a\u2028\u2029\u202f\u205f"
+                                  "\u3000]")
 
 try:
     from codecs import register_error, xmlcharrefreplace_errors
@@ -72,7 +81,7 @@
 class HTMLSerializer(object):
 
     # attribute quoting options
-    quote_attr_values = False
+    quote_attr_values = "legacy"  # be secure by default
     quote_char = '"'
     use_best_quote_char = True
 
@@ -108,9 +117,9 @@
         inject_meta_charset=True|False
           Whether it insert a meta element to define the character set of the
           document.
-        quote_attr_values=True|False
+        quote_attr_values="legacy"|"spec"|"always"
           Whether to quote attribute values that don't require quoting
-          per HTML5 parsing rules.
+          per legacy browser behaviour, when required by the standard, or always.
         quote_char=u'"'|u"'"
           Use given quote character for attribute quoting. Default is to
           use double quote unless attribute value contains a double quote,
@@ -239,10 +248,15 @@
                         (k not in booleanAttributes.get(name, tuple()) and
                          k not in booleanAttributes.get("", tuple())):
                         yield self.encodeStrict("=")
-                        if self.quote_attr_values:
+                        if self.quote_attr_values == "always" or len(v) == 0:
                             quote_attr = True
+                        elif self.quote_attr_values == "spec":
+                            quote_attr = quoteAttributeSpec.search(v) is not None
+                        elif self.quote_attr_values == "legacy":
+                            quote_attr = quoteAttributeLegacy.search(v) is not None
                         else:
-                            quote_attr = len(v) == 0 or quoteAttributeSpec.search(v)
+                            raise ValueError("quote_attr_values must be one of: "
+                                             "'always', 'spec', or 'legacy'")
                         v = v.replace("&", "&amp;")
                         if self.escape_lt_in_attrs:
                             v = v.replace("<", "&lt;")
```
