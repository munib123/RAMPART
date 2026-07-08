# Vulnerability: X-Backend-Server Header - Exposure
**Classification:** HEADERS
**Source:** Nuclei Template (`x-backend-server-header-detect.yaml`)

## Description
Detected that the website returned the X-Backend-Server header, which included potentially internal or hidden IP addresses or hostnames. By exposing these values, attackers might have attempted to circumvent security proxies and access these hosts directly.

## Secure Mitigation
disable revealing the X-Backend-Server header value.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/en
```

