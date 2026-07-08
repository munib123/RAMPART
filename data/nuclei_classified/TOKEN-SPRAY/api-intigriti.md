# Vulnerability: Intigriti-Researcher API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-intigriti.yaml`)

## Description
The Intigriti researcher API can be used to query information about Programs you have access to via our platform and Program activities you have access to via our platform

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.intigriti.com/external/researcher/v1/programs
```

