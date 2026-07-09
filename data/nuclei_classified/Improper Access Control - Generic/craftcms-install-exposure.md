# Nuclei Template: Craft CMS Installation Wizard Exposure
**Template ID:** craftcms-install-exposure
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`craftcms-install-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Craft CMS installation wizard was exposed, allowing attackers to complete the installation process and gain administrative access to the CMS.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin/install
```

## References
- https://craftcms.com/docs/4.x/installation.html
- https://craftcms.com/knowledge-base/securing-craft
