# Vulnerability: AbuseIPDB API - Test
**Classification:** CWE-200
**Source:** Nuclei Template (`api-abuseipdb.yaml`)

## Description
AbuseIPDB API test was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.abuseipdb.com/api/v2/report HTTP/1.1
Host: api.abuseipdb.com
Key: {{token}}
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 16

ip=127.0.0.1&categories=18,22&comment=SSH%20login%20attempts%20with%20user%20root.
```

