# Vulnerability: GoFile API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-gofile.yaml`)

## Description
Unlimited size file uploads for free

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.gofile.io/getAccountDetails?token={{token}}&allDetails=true
```

