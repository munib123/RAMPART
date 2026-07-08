# Vulnerability: XInclude Injection - Detection
**Classification:** DAST
**Source:** Nuclei Template (`xinclude-injection.yaml`)

## Description
XInclude is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an XInclude attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

