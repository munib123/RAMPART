# Vulnerability: Perforce Repository Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`perforce-repository.yaml`)

## Description
Detected an exposed .p4ignore file, which could have revealed ignored files, sensitive paths, or developer-specific information useful for further enumeration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.p4ignore
```

