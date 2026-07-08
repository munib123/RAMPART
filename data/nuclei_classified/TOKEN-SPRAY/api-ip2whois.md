# Vulnerability: IP2WHOIS API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-ip2whois.yaml`)

## Description
WHOIS domain name lookup

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.ip2whois.com/v2?key={{token}}&domain=daffa.tech&format=json
```

