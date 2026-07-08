# Vulnerability: pdflayer API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-pdflayer.yaml`)

## Description
HTML/URL to PDF

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.pdflayer.com/api/convert?access_key={{token}}&document_url=https://test.test HTTP/1.1
Host: api.pdflayer.com
```

