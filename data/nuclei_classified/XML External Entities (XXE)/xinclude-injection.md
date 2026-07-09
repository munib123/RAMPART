# Nuclei Template: XInclude Injection - Detection
**Template ID:** xinclude-injection
**Vulnerability Class:** XML External Entities (XXE)
**Severity:** High
**Source:** Nuclei Template (`xinclude-injection.yaml`)

## Vulnerability Information & PoC

## Description
XInclude is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an XInclude attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

## References
- https://d0pt3x.gitbook.io/passion/webapp-security/xxe-attacks/xinclude-attacks
