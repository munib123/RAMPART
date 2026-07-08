# Vulnerability: AEM Login Status
**Classification:** AEM
**Source:** Nuclei Template (`aem-login-status.yaml`)

## Description
LoginStatusServlet is exposed, it allows to bruteforce credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/sling/loginstatus
GET {{BaseURL}}/system/sling/loginstatus.css
GET {{BaseURL}}///system///sling///loginstatus
```

