# Vulnerability: Samba Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`samba-config.yaml`)

## Description
Samba configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/smb.conf
```

