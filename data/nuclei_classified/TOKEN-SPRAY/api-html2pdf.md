# Vulnerability: Html2PDF API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-html2pdf.yaml`)

## Description
HTML/URL to PDF

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.html2pdf.app/v1/generate?url=https://test.test&apiKey={{token}}
```

