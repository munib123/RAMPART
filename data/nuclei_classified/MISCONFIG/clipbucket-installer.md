# Vulnerability: ClipBucket Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`clipbucket-installer.yaml`)

## Description
ClipBucket is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cb_install/
```

