# Vulnerability: HIKVISION iSecure Center - Information Leak
**Classification:** INFOLEAK
**Source:** Nuclei Template (`hikvision-isecure-info-leak.yaml`)

## Description
HIKVISION iSecure Center comprehensive security management platform is an "integrated" and "intelligent" platform. By accessing equipment such as video surveillance, all-in-one card, parking lot, alarm detection and other systems, Hikvision comprehensive security management platform information exists Information leakage (internal network centralized account password) vulnerability can be decrypted through decryption software, username and password.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/conf/config.properties
```

