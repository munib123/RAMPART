# Vulnerability: Dribbble API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-dribbble.yaml`)

## Description
Dribbble is a self-promotion and social networking platform for digital designers and creatives

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.dribbble.com/v2/user?access_token={{token}}
```

