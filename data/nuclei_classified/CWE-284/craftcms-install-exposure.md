# Vulnerability: Craft CMS Installation Wizard Exposure
**Classification:** CWE-284
**Source:** Nuclei Template (`craftcms-install-exposure.yaml`)

## Description
Detected Craft CMS installation wizard was exposed, allowing attackers to complete the installation process and gain administrative access to the CMS.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/install
```

