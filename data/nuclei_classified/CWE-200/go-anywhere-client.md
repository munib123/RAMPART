# Vulnerability: GoAnywhere Web Client Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`go-anywhere-client.yaml`)

## Description
GoAnywhere Web Client login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webclient/Login.xhtml
```

