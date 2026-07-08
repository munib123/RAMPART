# Vulnerability: DS_Store File - Exposed
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ds-store-file.yaml`)

## Description
A .DS_Store file was found. This file may contain names of files that exist on the server, including backups or other files that aren't meant to be publicly available.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.DS_Store
```

