# Vulnerability: Adobe AEM ACS Common Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-acs-common.yaml`)

## Description
Adobe AEM ACS Common pages exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/etc/acs-commons/jcr-compare.html
GET {{BaseURL}}/etc/acs-commons/workflow-remover.html
GET {{BaseURL}}/etc/acs-commons/version-compare.html
GET {{BaseURL}}/etc/acs-commons/oak-index-manager.html
```

