# Vulnerability: Adobe AEM CRX Package Manager - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aem-crx-package-manager.yaml`)

## Description
Adobe AEM CRX Package Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/crx/packmgr/index.jsp
```

