# Vulnerability: Get Access Token Json
**Classification:** EXPOSURE
**Source:** Nuclei Template (`get-access-token-json.yaml`)

## Description
Internal file is exposed in Constant Contact Forms wordpress plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/constant-contact-forms/vendor/constantcontact/constantcontact/test/Json/Auth/get_access_token.json
GET {{BaseURL}}/wp-content/plugins/constant-contact-api-old/vendor/constantcontact/constantcontact/test/Json/Auth/get_access_token.json
```

