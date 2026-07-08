# Vulnerability: Open Proxy To External Network
**Classification:** CWE-441
**Source:** Nuclei Template (`open-proxy-external.yaml`)

## Description
The host is configured as a proxy which allows access to other hosts on the external network.

## Secure Mitigation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://test.s3.amazonaws.com HTTP/1.1
Host: test.s3.amazonaws.com

GET http://{{interactsh-url}} HTTP/1.1
Host: {{interactsh-url}}

GET / HTTP/1.1
Host: {{Hostname}}
```

