# Vulnerability: Synology DSM System Info - Detect
**Classification:** SYNOLOGY
**Source:** Nuclei Template (`synology-dsm-system-info.yaml`)

## Description
Detected the disclosure of Synology DiskStation Manager (DSM) system information via the SYNO.API.Info endpoint, identifying all available APIs, versions, and installed packages returned without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=all
```

