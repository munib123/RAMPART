# Vulnerability: D-Link DAP-1325 - Information Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`dlink-config-dump.yaml`)

## Description
Security vulnerability known as Unauthenticated access to settings or Unauthenticated configuration download. This vulnerability occurs when a device, such as a repeater, allows the download of user settings without requiring proper authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/ExportSettings.sh
```

