# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in python
**Pair ID:** 4805_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4805_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```python
Lines 19-59 of the vulnerable file.


__version__ = "4.4.0"

import logging
import six
from saml2.validate import valid_instance

try:
    from xml.etree import cElementTree as ElementTree

    if ElementTree.VERSION < '1.3.0':
        # cElementTree has no support for register_namespace
        # neither _namespace_map, thus we sacrify performance
        # for correctness
        from xml.etree import ElementTree
except ImportError:
    try:
        import cElementTree as ElementTree
    except ImportError:
        from elementtree import ElementTree

root_logger = logging.getLogger(__name__)
root_logger.level = logging.NOTSET

NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
# TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:assertion}%s'
# XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'

NAMEID_FORMAT_EMAILADDRESS = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

# These are defined in saml2.saml
# NAME_FORMAT_UNSPECIFIED = (
#    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
# NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
# NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
         import cElementTree as ElementTree
     except ImportError:
         from elementtree import ElementTree
+import defusedxml.ElementTree
 
 root_logger = logging.getLogger(__name__)
 root_logger.level = logging.NOTSET
@@ -87,7 +88,7 @@
     """
     if not isinstance(xml_string, six.binary_type):
         xml_string = xml_string.encode('utf-8')
-    tree = ElementTree.fromstring(xml_string)
+    tree = defusedxml.ElementTree.fromstring(xml_string)
     return create_class_from_element_tree(target_class, tree)
 
 
@@ -269,7 +270,7 @@
 
 
 def extension_element_from_string(xml_string):
-    element_tree = ElementTree.fromstring(xml_string)
+    element_tree = defusedxml.ElementTree.fromstring(xml_string)
     return _extension_element_from_element_tree(element_tree)
 
 
```
