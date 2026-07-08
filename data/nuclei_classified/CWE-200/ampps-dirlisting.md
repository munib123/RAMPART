# Vulnerability: AMPPS by Softaculous Panel - Directory Listing - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ampps-dirlisting.yaml`)

## Description
AMPPS by Softaculous panel directory listing was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/client/
GET {{BaseURL}}/files/
GET {{BaseURL}}/icons/
```

