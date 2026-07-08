# Vulnerability: CraftMyPDF API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-craftmypdf.yaml`)

## Description
Generate PDF documents from templates with a drop-and-drop editor and a simple API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.craftmypdf.com/v1/list-templates?limit=300&offset=0 HTTP/1.1
Host: api.craftmypdf.com
Content-Type: application/json
X-API-KEY: {{token}}
```

