# Vulnerability: Well-Known MTA-STS Policy
**Classification:** WELL-KNOWN
**Source:** Nuclei Template (`mta-sts-exposure.yaml`)

## Description
Detects SMTP MTA-STS policy file (RFC 8461).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/mta-sts.txt
```

