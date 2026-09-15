# Nuclei Template: Grails Admin Console Panel - Detect
**Template ID:** grails-database-admin-console
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`grails-database-admin-console.yaml`)

## Vulnerability Information & PoC

## Description
Grails Admin Console panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/dbconsole/
GET {{BaseURL}}/h2-console/
```

## References
- https://www.acunetix.com/vulnerabilities/web/grails-database-console/
- http://h2database.com/html/quickstart.html#h2_console
