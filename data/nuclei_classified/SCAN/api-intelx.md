# Vulnerability: Intelligence X API Test
**Classification:** SCAN
**Source:** Nuclei Template (`api-intelx.yaml`)

## Description
Intelligence X is a search engine and data archive. Search Tor, I2P, data leaks and the public web by email, domain, IP, CIDR, Bitcoin address and more.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://2.intelx.io/authenticate/info
```

