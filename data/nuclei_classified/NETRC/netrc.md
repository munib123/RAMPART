# Vulnerability: Netrc - Config File Discovery
**Classification:** NETRC
**Source:** Nuclei Template (`netrc.yaml`)

## Description
Netrc configuration file was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.netrc
GET {{BaseURL}}/_netrc
```

