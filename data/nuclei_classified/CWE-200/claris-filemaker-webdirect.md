# Vulnerability: Claris FileMaker WebDirect Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`claris-filemaker-webdirect.yaml`)

## Description
Claris FileMaker WebDirect panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fmi/webd/
```

