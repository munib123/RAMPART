# Vulnerability: phpMyAdmin - Full Path Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`phpmyadmin-fpd.yaml`)

## Description
Detected potential Full Path Disclosure (FPD) via directly accessible phpMyAdmin files that may throw PHP errors revealing filesystem paths when error display is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
GET {{BaseURL}}/phpmyadmin/libraries/advisory_rules_generic.php
GET {{BaseURL}}/phpmyadmin/libraries/phpseclib/Crypt/AES.php
GET {{BaseURL}}/phpmyadmin/libraries/phpseclib/Crypt/Rijndael.php
```

