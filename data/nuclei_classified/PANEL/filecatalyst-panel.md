# Vulnerability: FileCatalyst File Transfer Solution - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`filecatalyst-panel.yaml`)

## Description
Detects the presence of FileCatalyst file transfer solution login panel

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/workflow/jsp/logon.jsp
```

