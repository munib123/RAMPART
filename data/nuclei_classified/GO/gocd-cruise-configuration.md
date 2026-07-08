# Vulnerability: GoCd Cruise Configuration disclosure
**Classification:** GO
**Source:** Nuclei Template (`gocd-cruise-configuration.yaml`)

## Description
GoCd Cruise Configuration is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/go/add-on/business-continuity/api/cruise_config
```

