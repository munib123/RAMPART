# Nuclei Template: Open Proxy To External Network
**Template ID:** open-proxy-external
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**CWE:** CWE-441
**Source:** Nuclei Template (`open-proxy-external.yaml`)

## Vulnerability Information & PoC

## Description
The host is configured as a proxy which allows access to other hosts on the external network.

## Steps to reproduce / Exploit Payload
```http
GET https://test.s3.amazonaws.com HTTP/1.1
Host: test.s3.amazonaws.com

GET http://{{interactsh-url}} HTTP/1.1
Host: {{interactsh-url}}

GET / HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## References
- https://en.wikipedia.org/wiki/Open_proxy
- https://www.acunetix.com/vulnerabilities/web/apache-configured-to-run-as-proxy/
