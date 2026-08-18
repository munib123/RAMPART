# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 4602_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4602_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 1-29 of the vulnerable file.

from __future__ import absolute_import
import re
from collections import namedtuple

from ..exceptions import LocationParseError
from ..packages import six, rfc3986
from ..packages.rfc3986.exceptions import RFC3986Exception, ValidationError
from ..packages.rfc3986.validators import Validator


url_attrs = ['scheme', 'auth', 'host', 'port', 'path', 'query', 'fragment']

# We only want to normalize urls with an HTTP(S) scheme.
# urllib3 infers URLs without a scheme (None) to be http.
NORMALIZABLE_SCHEMES = ('http', 'https', None)

# Regex for detecting URLs with schemes. RFC 3986 Section 3.1
SCHEME_REGEX = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+\-]*:|/)")


class Url(namedtuple('Url', url_attrs)):
    """
    Data structure for representing an HTTP URL. Used as a return value for
    :func:`parse_url`. Both the scheme and host are normalized as they are
    both case-insensitive according to RFC 3986.
    """
    __slots__ = ()

    def __new__(cls, scheme=None, auth=None, host=None, port=None, path=None,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 from ..packages import six, rfc3986
 from ..packages.rfc3986.exceptions import RFC3986Exception, ValidationError
 from ..packages.rfc3986.validators import Validator
+from ..packages.rfc3986 import abnf_regexp, normalizers, compat, misc
 
 
 url_attrs = ['scheme', 'auth', 'host', 'port', 'path', 'query', 'fragment']
@@ -16,6 +17,9 @@
 
 # Regex for detecting URLs with schemes. RFC 3986 Section 3.1
 SCHEME_REGEX = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+\-]*:|/)")
+
+PATH_CHARS = abnf_regexp.UNRESERVED_CHARS_SET | abnf_regexp.SUB_DELIMITERS_SET | {':', '@', '/'}
+QUERY_CHARS = FRAGMENT_CHARS = PATH_CHARS | {'?'}
 
 
 class Url(namedtuple('Url', url_attrs)):
@@ -136,6 +140,37 @@
     return s[:min_idx], s[min_idx + 1:], min_delim
 
 
+def _encode_invalid_chars(component, allowed_chars, encoding='utf-8'):
+    """Percent-encodes a URI component without reapplying
+    onto an already percent-encoded component. Based on
+    rfc3986.normalizers.encode_component()
+    """
+    if component is None:
+        return component
+
+    # Try to see if the component we're encoding is already percent-encoded
+    # so we can skip all '%' characters but still encode all others.
+    percent_encodings = len(normalizers.PERCENT_MATCHER.findall(
+                            compat.to_str(component, encoding)))
+
+    uri_bytes = component.encode('utf-8', 'surrogatepass')
+    is_percent_encoded = percent_encodings == uri_bytes.count(b'%')
+
+    encoded_component = bytearray()
+
+    for i in range(0, len(uri_bytes)):
+        # Will return a single character bytestring on both Python 2 & 3
+        byte = uri_bytes[i:i+1]
+        byte_ord = ord(byte)
+        if ((is_percent_encoded and byte == b'%')
+                or (byte_ord < 128 and byte.decode() in allowed_chars)):
+            encoded_component.extend(byte)
+            continue
+        encoded_component.extend('%{0:02x}'.format(byte_ord).encode().upper())
+
+    return encoded_component.decode(encoding)
+
+
 def parse_url(url):
     """
     Given a url, return a parsed :class:`.Url` namedtuple. Best-effort is
@@ -160,8 +195,6 @@
         return Url()
 
     is_string = not isinstance(url, six.binary_type)
-    if not is_string:
-        url = url.decode("utf-8")
 
     # RFC 3986 doesn't like URLs that have a host but don't start
     # with a scheme and we support URLs like that so we need to
@@ -170,11 +203,6 @@
     # off and given an empty scheme anyways.
     if not SCHEME_REGEX.search(url):
         url = "//" + url
-
-    try:
-        iri_ref = rfc3986.IRIReference.from_string(url, encoding="utf-8")
-    except (ValueError, RFC3986Exception):
-        six.raise_from(LocationParseError(url), None)
 
     def idna_encode(name):
         if name and any([ord(x) > 128 for x in name]):
@@ -188,8 +216,18 @@
                 raise LocationParseError(u"Name '%s' is not a valid IDNA label" % name)
         return name
 
-    has_authority = iri_ref.authority is not None
-    uri_ref = iri_ref.encode(idna_encoder=idna_encode)
+    try:
+        split_iri = misc.IRI_MATCHER.match(compat.to_str(url)).groupdict()
+        iri_ref = rfc3986.IRIReference(
+            split_iri['scheme'], split_iri['authority'],
+            _encode_invalid_chars(split_iri['path'], PATH_CHARS),
+            _encode_invalid_chars(split_iri['query'], QUERY_CHARS),
+            _encode_invalid_chars(split_iri['fragment'], FRAGMENT_CHARS)
+        )
+        has_authority = iri_ref.authority is not None
+        uri_ref = iri_ref.encode(idna_encoder=idna_encode)
+    except (ValueError, RFC3986Exception):
+        return six.raise_from(LocationParseError(url), None)
 
     # rfc3986 strips the authority if it's invalid
     if has_authority and uri_ref.authority is None:
@@ -209,7 +247,7 @@
             *validator.COMPONENT_NAMES
         ).validate(uri_ref)
     except ValidationError:
-        six.raise_from(LocationParseError(url), None)
+        return six.raise_from(LocationParseError(url), None)
 
     # For the sake of backwards compatibility we put empty
     # string values for path if there are any defined values
```
