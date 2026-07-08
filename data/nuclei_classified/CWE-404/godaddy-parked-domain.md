# Vulnerability: GoDaddy Parked Domain - Subdomain Takeover
**Classification:** CWE-404
**Source:** Nuclei Template (`godaddy-parked-domain.yaml`)

## Description
Detects potential subdomain takeover when a subdomain's CNAME points to a domain that is parked or listed for sale on GoDaddy. An attacker could purchase the target domain and gain full control over the subdomain, enabling phishing, cookie theft, or malicious content serving.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/lander
```

