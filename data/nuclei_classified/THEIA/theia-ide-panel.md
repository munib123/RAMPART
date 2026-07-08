# Vulnerability: Eclipse Theia IDE Panel - Detect
**Classification:** THEIA
**Source:** Nuclei Template (`theia-ide-panel.yaml`)

## Description
Detected Eclipse Theia IDE panel was exposed. Theia is an extensible platform for multi-language Cloud and Desktop IDEs. Exposed panels may have allowed unauthenticated access to development environments and terminal.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

