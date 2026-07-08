# Vulnerability: Adobe AEM Disk Usage Information Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-disk-usage.yaml`)

## Description
Adobe AEM Disk Usage Information is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/etc/reports/diskusage.html
GET {{BaseURL}}/etc/reports/diskusage.html?path=/content/dam
```

