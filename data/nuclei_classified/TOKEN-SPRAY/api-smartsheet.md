# Vulnerability: Smartsheet API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-smartsheet.yaml`)

## Description
Allows you to programmatically access and Smartsheet data and account information

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.smartsheet.com/2.0/home?include=source
```

