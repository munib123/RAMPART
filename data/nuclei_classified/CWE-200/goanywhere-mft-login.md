# Vulnerability: GoAnywhere Managed File Transfer Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`goanywhere-mft-login.yaml`)

## Description
GoAnywhere Managed File Transfer login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/goanywhere/auth/Login.xhtml
GET {{BaseURL}}/webclient/Login.xhtml
```

