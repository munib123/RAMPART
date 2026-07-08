# Vulnerability: Adobe AEM Installed OSGI Bundles
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-osgi-bundles.yaml`)

## Description
Adobe AEM Installed OSGI Bundles leaked.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bin.tidy.infinity.json
```

