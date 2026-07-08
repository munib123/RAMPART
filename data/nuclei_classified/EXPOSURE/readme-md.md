# Vulnerability: README.md file disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`readme-md.yaml`)

## Description
Internal documentation file often used in projects which can contain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/README.md
```

