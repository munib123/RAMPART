# Vulnerability: Netlify Headers Configuration - Exporsure
**Classification:** NETLIFY
**Source:** Nuclei Template (`netlify-headers-config-exposure.yaml`)

## Description
Detected publicly accessible Netlify configuration files such as _headers, headers, or netlify.toml. Exposure of these files may disclose security header settings, routing rules, authentication mechanisms, or other sensitive deployment information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_headers
GET {{BaseURL}}/headers
GET {{BaseURL}}/netlify.toml
```

