# Vulnerability: SmarterStats Setup Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`smarterstats-setup.yaml`)

## Description
SmarterStats Setup is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Admin/frmWelcome.aspx
```

