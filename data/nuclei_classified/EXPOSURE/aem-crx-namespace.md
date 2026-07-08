# Vulnerability: Adobe AEM CRX Namespace Editor Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`aem-crx-namespace.yaml`)

## Description
Adobe AEM CRX Namespace Editor is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/crx/explorer/ui/namespace_editor.jsp
```

