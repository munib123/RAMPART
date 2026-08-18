# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in python
**Pair ID:** 4805_2
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4805_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```python
Lines 20-60 of the vulnerable file.

from saml2.sigver import RESP_ORDER
from saml2.sigver import SIGNER_ALGS
import six
from saml2.xmldsig import SIG_ALLOWED_ALG

logger = logging.getLogger(__name__)

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

NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="%s" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <input type="submit" value="Submit" />
</form>"""


def http_form_post_message(message, location, relay_state="",
                           typ="SAMLRequest", **kwargs):
    """The HTTP POST binding defines a mechanism by which SAML protocol
    messages may be transmitted within the base64-encoded content of a
    HTML form control.

    :param message: The message
    :param location: Where the form should be posted to
    :param relay_state: for preserving and conveying state information
    :return: A tuple containing header information and a HTML message.
    """
    response = ["<head>", """<title>SAML 2.0 POST</title>""", "</head><body>"]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,7 @@
         import cElementTree as ElementTree
     except ImportError:
         from elementtree import ElementTree
+import defusedxml.ElementTree
 
 NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
 FORM_SPEC = """<form method="post" action="%s">
@@ -235,7 +236,7 @@
     :param text: The SOAP object as XML
     :return: header parts and body as saml.samlbase instances
     """
-    envelope = ElementTree.fromstring(text)
+    envelope = defusedxml.ElementTree.fromstring(text)
     assert envelope.tag == '{%s}Envelope' % NAMESPACE
 
     # print(len(envelope))
```
