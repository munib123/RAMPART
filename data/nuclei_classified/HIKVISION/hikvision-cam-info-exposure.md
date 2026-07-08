# Vulnerability: Hikvision IP Camera - Info Exposure
**Classification:** HIKVISION
**Source:** Nuclei Template (`hikvision-cam-info-exposure.yaml`)

## Description
Unauthenticated exposure of sensitive endpoints was detected on vulnerable Hikvision IP cameras. This included live snapshot feeds, encrypted configuration files, and full user credential XML through CVE-2021-36260 exploit chaining and bypass logic.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Security/users?auth={{b64auth}}
```

