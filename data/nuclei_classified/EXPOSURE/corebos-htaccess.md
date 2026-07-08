# Vulnerability: CoreBos - .htaccess File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`corebos-htaccess.yaml`)

## Description
CoreBos was discovered to have .htaccess file exposed to public which includes sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/htaccess.txt
```

