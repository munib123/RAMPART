# Vulnerability: Joomla! - Full Path Disclosure
**Classification:** JOOMLA
**Source:** Nuclei Template (`joomla-fpd.yaml`)

## Description
Detects full path disclosure in Joomla! sending requests to specific paths and identifying fatal error stack traces that leaked absolute filesystem paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/administrator/manifests/files/joomla.xml
GET {{BaseURL}}/language/en-GB/en-GB.xml
GET {{BaseURL}}/README.txt
GET {{BaseURL}}/modules/custom.xml
GET {{BaseURL}}
GET {{BaseURL}}/libraries/phputf8/utils/bad.php
GET {{BaseURL}}/libraries/php-inputfilter/inputfilter.php
GET {{BaseURL}}/libraries/php-fileupload/fileupload.php
GET {{BaseURL}}/libraries/joomla/filesystem/archive/archive.php
GET {{BaseURL}}/libraries/joomla/filesystem/archive/tar.php
GET {{BaseURL}}/libraries/joomla/filesystem/archive/zip.php
GET {{BaseURL}}/libraries/phpmailer/phpmailer.php
GET {{BaseURL}}/libraries/phputf8/utils/unicode.php
```

