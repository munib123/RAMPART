# Vulnerability: Nacos - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nacos-version.yaml`)

## Description
Nacos was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/console/server/state?accessToken=&username=
GET {{BaseURL}}/nacos/v1/console/server/state?accessToken=&username=
```

