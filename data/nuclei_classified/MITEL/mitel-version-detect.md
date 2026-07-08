# Vulnerability: Mitel MiCollab Unified Communications Server (UCS) - Detect
**Classification:** MITEL
**Source:** Nuclei Template (`mitel-version-detect.yaml`)

## Description
Mitel MiCollab UCS version disclosure via the /ucs/micollab/version.json endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ucs/micollab/version.json
```

