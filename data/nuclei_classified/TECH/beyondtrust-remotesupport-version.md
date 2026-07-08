# Vulnerability: BeyondTrust Remote Support Version - Detect
**Classification:** TECH
**Source:** Nuclei Template (`beyondtrust-remotesupport-version.yaml`)

## Description
Detects and extracts version information from BeyondTrust Remote Support installations by querying the /get_rdf endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/get_rdf?comp=sdcust&locale_code=en-us
```

