# Vulnerability: Magento Connect Manager Installer - Detect
**Classification:** MAGENTO
**Source:** Nuclei Template (`magento-downloader-panel.yaml`)

## Description
Magento Connect Manager installer was detected. The software, available via /downloader/ location, requires Magento admin rights and uses the same authorization methods as for backend. If an attacker locates a matching pair of login/password, the installation will be compromised. An attacker can then discover backend URL for login (even if it is customized as described in Securing Magento /admin/) and install a Filesystem extension to obtain full access to all files and finally the database.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/downloader/
```

