# Vulnerability: Vercel Config File - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`vercel-config-file.yaml`)

## Description
Vercel Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vercel.json
```

