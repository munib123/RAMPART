# Vulnerability: ThinkCMF - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`thinkcmf-lfi.yaml`)

## Description
ThinkCMF is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?a=display&templateFile=README.md
```

