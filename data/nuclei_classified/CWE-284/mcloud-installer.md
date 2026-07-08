# Vulnerability: mCloud Panel - Installer
**Classification:** CWE-284
**Source:** Nuclei Template (`mcloud-installer.yaml`)

## Description
mCloud installer was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/clusterList
```

