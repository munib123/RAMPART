# Vulnerability: Missing Subresource Integrity
**Classification:** CWE-353
**Source:** Nuclei Template (`missing-sri.yaml`)

## Description
Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

