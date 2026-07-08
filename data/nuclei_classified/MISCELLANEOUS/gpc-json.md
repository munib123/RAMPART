# Vulnerability: Global Privacy Control (GPC) File Disclosure
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`gpc-json.yaml`)

## Description
The website defines a Global Privacy Control policy.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/.well-known/gpc.json
GET {{RootURL}}/gpc.json
```

