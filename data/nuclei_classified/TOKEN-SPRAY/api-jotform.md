# Vulnerability: Jotform API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-jotform.yaml`)

## Description
Jotform is a powerful online form builder that makes it easy to create robust forms and collect important data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.jotform.com/user?apiKey={{token}}
```

