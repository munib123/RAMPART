# Vulnerability: Open Proxy to Other Web Ports via Proxy's localhost Interface
**Classification:** CWE-441,CWE-918
**Source:** Nuclei Template (`open-proxy-localhost.yaml`)

## Description
The host is configured as a proxy which allows access to web ports on the host's internal interface.

## Secure Mitigation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## Vulnerable Code Pattern / Exploit Payload
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

