# Vulnerability: Vagrantfile Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`vagrantfile-exposure.yaml`)

## Description
Vagrantfile is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Vagrantfile
```

