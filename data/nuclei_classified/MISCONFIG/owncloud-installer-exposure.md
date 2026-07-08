# Vulnerability: OwnCloud Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`owncloud-installer-exposure.yaml`)

## Description
OwnCloud is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/owncloud/
```

