# Vulnerability: Apache License File
**Classification:** EXPOSURE
**Source:** Nuclei Template (`apache-licenserc.yaml`)

## Description
Apache License file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.licenserc.yaml
```

