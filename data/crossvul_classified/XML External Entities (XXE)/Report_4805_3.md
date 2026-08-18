# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in python
**Pair ID:** 4805_3
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4805_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```python
Lines 2-42 of the vulnerable file.

# -*- coding: utf-8 -*-
#

"""
Suppport for the client part of the SAML2.0 SOAP binding.
"""
import logging

from saml2 import create_class_from_element_tree
from saml2.samlp import NAMESPACE as SAMLP_NAMESPACE
from saml2.schema import soapenv

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        #noinspection PyUnresolvedReferences
        from elementtree import ElementTree


logger = logging.getLogger(__name__)


class XmlParseError(Exception):
    pass


class WrongMessageType(Exception):
    pass


def parse_soap_enveloped_saml_response(text):
    tags = ['{%s}Response' % SAMLP_NAMESPACE,
            '{%s}LogoutResponse' % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_logout_response(text):
    tags = ['{%s}Response' % SAMLP_NAMESPACE,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
     except ImportError:
         #noinspection PyUnresolvedReferences
         from elementtree import ElementTree
+import defusedxml.ElementTree
 
 
 logger = logging.getLogger(__name__)
@@ -133,7 +134,7 @@
     :param expected_tags: What the tag of the SAML thingy is expected to be.
     :return: SAML thingy as a string
     """
-    envelope = ElementTree.fromstring(text)
+    envelope = defusedxml.ElementTree.fromstring(text)
 
     # Make sure it's a SOAP message
     assert envelope.tag == '{%s}Envelope' % soapenv.NAMESPACE
@@ -183,7 +184,7 @@
     :return: The body and headers as class instances
     """
     try:
-        envelope = ElementTree.fromstring(text)
+        envelope = defusedxml.ElementTree.fromstring(text)
     except Exception as exc:
         raise XmlParseError("%s" % exc)
 
@@ -209,7 +210,7 @@
     :return: dictionary with two keys "body"/"header"
     """
     try:
-        envelope = ElementTree.fromstring(text)
+        envelope = defusedxml.ElementTree.fromstring(text)
     except Exception as exc:
         raise XmlParseError("%s" % exc)
 
```
