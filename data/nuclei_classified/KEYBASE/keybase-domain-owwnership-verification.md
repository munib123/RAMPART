# Vulnerability: Keybase Domain Ownership Verification
**Classification:** KEYBASE
**Source:** Nuclei Template (`keybase-domain-owwnership-verification.yaml`)

## Description
Detects presence of keybase.txt used to prove domain ownership via Keybase identity.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/keybase.txt
```

