# Vulnerability: WordPress license file disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-license-file.yaml`)

## Description
Leaked WordPress license file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/license.txt
```

