# Vulnerability: Adobe AEM Offloading Browser
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-offloading-browser.yaml`)

## Description
Adobe AEM Offloading Browser is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/libs/granite/offloading/content/view.html
```

