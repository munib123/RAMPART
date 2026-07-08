# Vulnerability: CRXDE Lite - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`crxde-lite.yaml`)

## Description
CRXDE Lite exposure was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/crx/de/index.jsp
```

