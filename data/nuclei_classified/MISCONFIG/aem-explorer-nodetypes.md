# Vulnerability: Adobe AEM Explorer NodeTypes Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-explorer-nodetypes.yaml`)

## Description
Adobe AEM Explorer NodeTypes is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/crx/explorer/nodetypes/index.jsp
```

