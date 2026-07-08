# Vulnerability: ESPEasy Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`espeasy-installer.yaml`)

## Description
ESPEasy is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ESPEasy
```

