# Vulnerability: Saia PCD Web Server Panel - Detect
**Classification:** SAIA
**Source:** Nuclei Template (`saia-pcd-panel.yaml`)

## Description
Saia PCD Web Server panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pwdform.htm
```

