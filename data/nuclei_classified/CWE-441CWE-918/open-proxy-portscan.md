# Vulnerability: Open Proxy to Ports on the Proxy's localhost Interface
**Classification:** CWE-441,CWE-918
**Source:** Nuclei Template (`open-proxy-portscan.yaml`)

## Description
The host is configured as a proxy which allows access to its internal interface

## Secure Mitigation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## Vulnerable Code Pattern / Exploit Payload
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

