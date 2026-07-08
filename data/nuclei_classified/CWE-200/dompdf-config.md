# Vulnerability: DomPDF - Configuration Page
**Classification:** CWE-200
**Source:** Nuclei Template (`dompdf-config.yaml`)

## Description
DOMPDF Configuration page was detected, which contains paths, library versions and other potentially sensitive information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/www/setup.php
GET {{BaseURL}}/dompdf/dompdf/www/setup.php
GET {{BaseURL}}/js/dompdf/www/setup.php
GET {{BaseURL}}/portal/application/libraries/dompdf/www/setup.php
GET {{BaseURL}}/sites/all/libraries/dompdf/www/setup.php
GET {{BaseURL}}/vendor/dompdf/dompdf/www/setup.php
```

