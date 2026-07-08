# Vulnerability: QloApps - Installation
**Classification:** INSTALL
**Source:** Nuclei Template (`qloapps-installer.yaml`)

## Description
QloApps Installation Assistant panel exposure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

