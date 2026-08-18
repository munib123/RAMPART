# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in python
**Pair ID:** 2503_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2503_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```python
Lines 1-36 of the vulnerable file.

import base64
import re
from datetime import datetime
import logging
import ssl
from xml.etree import ElementTree

import iso8601
import six

import recurly
import recurly.errors
from recurly.link_header import parse_link_value
from six.moves import http_client
from six.moves.urllib.parse import urlencode, urljoin, urlsplit


class Money(object):

    """An amount of money in one or more currencies."""

    def __init__(self, *args, **kwargs):
        if args and kwargs:
            raise ValueError("Money may be single currency or multi-currency but not both")
        elif kwargs:
            self.currencies = dict(kwargs)
        elif args and len(args) > 1:
            raise ValueError("Multi-currency Money must be instantiated with codes")
        elif args:
            self.currencies = { recurly.DEFAULT_CURRENCY: args[0] }
        else:
            self.currencies = dict()

    @classmethod
    def from_element(cls, elem):
        currency = dict()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,8 +12,7 @@
 import recurly.errors
 from recurly.link_header import parse_link_value
 from six.moves import http_client
-from six.moves.urllib.parse import urlencode, urljoin, urlsplit
-
+from six.moves.urllib.parse import urlencode, urlsplit, quote
 
 class Money(object):
 
@@ -338,7 +337,8 @@
         can be directly requested with this method.
 
         """
-        url = urljoin(recurly.base_uri(), cls.member_path % (uuid,))
+        uuid = quote(str(uuid))
+        url = recurly.base_uri() + (cls.member_path % (uuid,))
         resp, elem = cls.element_for_url(url)
         return cls.from_element(elem)
 
@@ -606,7 +606,7 @@
         parameters.
 
         """
-        url = urljoin(recurly.base_uri(), cls.collection_path)
+        url = recurly.base_uri() + cls.collection_path
         if kwargs:
             url = '%s?%s' % (url, urlencode(kwargs))
         return Page.page_for_url(url)
@@ -616,7 +616,7 @@
         """Return a count of server side resources given
         filtering arguments in kwargs.
         """
-        url = urljoin(recurly.base_uri(), cls.collection_path)
+        url = recurly.base_uri() + cls.collection_path
         if kwargs:
             url = '%s?%s' % (url, urlencode(kwargs))
         return Page.count_for_url(url)
@@ -638,7 +638,7 @@
         return self.put(self._url)
 
     def _create(self):
-        url = urljoin(recurly.base_uri(), self.collection_path)
+        url = recurly.base_uri() + self.collection_path
         return self.post(url)
 
     def put(self, url):
```
