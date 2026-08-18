# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 652_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `652_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

from __future__ import unicode_literals
from itertools import chain
import re
import string

import six
from xml.sax.saxutils import unescape

import html5lib
from html5lib.constants import (
    entities,
    namespaces,
    prefixes,
    tokenTypes,
)
try:
    from html5lib.constants import ReparseException
except ImportError:
    # html5lib-python 1.0 changed the name
    from html5lib.constants import _ReparseException as ReparseException
from html5lib.filters.base import Filter
from html5lib.filters import sanitizer
from html5lib.serializer import HTMLSerializer
from html5lib._tokenizer import HTMLTokenizer
from html5lib._trie import Trie

from bleach.utils import alphabetize_attributes, force_unicode
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 import string
 
 import six
+from six.moves.urllib.parse import urlparse
 from xml.sax.saxutils import unescape
 
 import html5lib
@@ -27,8 +28,11 @@
 from bleach.utils import alphabetize_attributes, force_unicode
 
 
+#: Map of entity name to expanded entity
+ENTITIES = entities
+
 #: Trie of html entity string -> character representation
-ENTITIES_TRIE = Trie(entities)
+ENTITIES_TRIE = Trie(ENTITIES)
 
 #: List of allowed tags
 ALLOWED_TAGS = [
@@ -79,13 +83,61 @@
 INVISIBLE_REPLACEMENT_CHAR = '?'
 
 
+def convert_entity(value):
+    """Convert an entity (minus the & and ; part) into what it represents
+
+    This handles numeric, hex, and text entities.
+
+    :arg value: the string (minus the ``&`` and ``;`` part) to convert
+
+    :returns: unicode character
+
+    """
+    if value[0] == '#':
+        if value[1] in ('x', 'X'):
+            return six.unichr(int(value[2:], 16))
+        return six.unichr(int(value[1:], 10))
+
+    return ENTITIES[value]
+
+
+def convert_entities(text):
+    """Converts all found entities in the text
+
+    :arg text: the text to convert entities in
+
+    :returns: unicode text with converted entities
+
+    """
+    if '&' not in text:
+        return text
+
+    new_text = []
+    for part in next_possible_entity(text):
+        if not part:
+            continue
+
+        if part.startswith('&'):
+            entity = match_entity(part)
+            if entity is not None:
+                new_text.append(convert_entity(entity))
+                remainder = part[len(entity) + 2:]
+                if part:
+                    new_text.append(remainder)
+                continue
+
+        new_text.append(part)
+
+    return u''.join(new_text)
+
+
 class BleachHTMLTokenizer(HTMLTokenizer):
     def consumeEntity(self, allowedChar=None, fromAttribute=False):
         # We don't want to consume and convert entities, so this overrides the
         # html5lib tokenizer's consumeEntity so that it's now a no-op.
         #
         # However, when that gets called, it's consumed an &, so we put that in
-        # the steam.
+        # the stream.
         if fromAttribute:
             self.currentToken['data'][-1][1] += '&'
 
@@ -479,14 +531,68 @@
                     new_tokens.append({'type': 'Entity', 'name': entity})
                     # Length of the entity plus 2--one for & at the beginning
                     # and and one for ; at the end
-                    part = part[len(entity) + 2:]
-                    if part:
-                        new_tokens.append({'type': 'Characters', 'data': part})
+                    remainder = part[len(entity) + 2:]
+                    if remainder:
+                        new_tokens.append({'type': 'Characters', 'data': remainder})
                     continue
 
             new_tokens.append({'type': 'Characters', 'data': part})
 
         return new_tokens
+
+    def sanitize_uri_value(self, value, allowed_protocols):
+        """Checks a uri value to see if it's allowed
+
+        :arg value: the uri value to sanitize
+        :arg allowed_protocols: list of allowed protocols
+
+        :returns: allowed value or None
+
+        """
+        # NOTE(willkg): This transforms the value into one that's easier to
+        # match and verify, but shouldn't get returned since it's vastly
+        # different than the original value.
+
+        # Convert all character entities in the value
+        new_value = convert_entities(value)
+
+        # Nix backtick, space characters, and control characters
+        new_value = re.sub(
+            "[`\000-\040\177-\240\s]+",
+            '',
+            new_value
+        )
+
+        # Remove REPLACEMENT characters
+        new_value = new_value.replace('\ufffd', '')
+
+        # Lowercase it--this breaks the value, but makes it easier to match
+        # against
+        new_value = new_value.lower()
+
+        # Drop attributes with uri values that have protocols that aren't
+        # allowed
+        parsed = urlparse(new_value)
+        if parsed.scheme:
+            # If urlparse found a scheme, check that
+            if parsed.scheme in allowed_protocols:
+                return value
+
+        else:
+            # Allow uris that are just an anchor
+            if new_value.startswith('#'):
+                return value
+
+            # Handle protocols that urlparse doesn't recognize like "myprotocol"
+            if ':' in new_value and new_value.split(':')[0] in allowed_protocols:
+                return value
+
+            # If there's no protocol/scheme specified, then assume it's "http"
+            # and see if that's allowed
+            if 'http' in allowed_protocols:
+                return value
+
+        return None
 
     def allow_token(self, token):
         """Handles the case where we're allowing the tag"""
@@ -508,21 +614,13 @@
                 if not self.attr_filter(token['name'], name, val):
                     continue
 
-                # Look at attributes that have uri values
+                # Drop attributes with uri values that use a disallowed protocol
+                # Sanitize attributes with uri values
                 if namespaced_name in self.attr_val_is_uri:
-                    val_unescaped = re.sub(
-                        "[`\000-\040\177-\240\s]+",
-                        '',
-                        unescape(val)).lower()
-
-                    # Remove replacement characters from unescaped characters.
-                    val_unescaped = val_unescaped.replace("\ufffd", "")
-
-                    # Drop attributes with uri values that have protocols that
-                    # aren't allowed
-                    if (re.match(r'^[a-z0-9][-+.a-z0-9]*:', val_unescaped) and
-                            (val_unescaped.split(':')[0] not in self.allowed_protocols)):
+                    new_value = self.sanitize_uri_value(val, self.allowed_protocols)
+                    if new_value is None:
                         continue
+                    val = new_value
 
                 # Drop values in svg attrs with non-local IRIs
                 if namespaced_name in self.svg_attr_val_allows_ref:
```
