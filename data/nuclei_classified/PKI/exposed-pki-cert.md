# Vulnerability: Exposed Internal PKI Infrastructure - Detect
**Classification:** PKI
**Source:** Nuclei Template (`exposed-pki-cert.yaml`)

## Description
Detects exposed internal PKI infrastructure including CRL distribution points and OCSP responders

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

