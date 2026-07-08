# Vulnerability: Icecast Config - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`icecast-config.yaml`)

## Description
Icecast Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/icecast.xml
```

