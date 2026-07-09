# Nuclei Template: DomPDF - Configuration Page
**Template ID:** dompdf-config
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`dompdf-config.yaml`)

## Vulnerability Information & PoC

## Description
DOMPDF Configuration page was detected, which contains paths, library versions and other potentially sensitive information

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/www/setup.php
GET {{BaseURL}}/dompdf/dompdf/www/setup.php
GET {{BaseURL}}/js/dompdf/www/setup.php
GET {{BaseURL}}/portal/application/libraries/dompdf/www/setup.php
GET {{BaseURL}}/sites/all/libraries/dompdf/www/setup.php
GET {{BaseURL}}/vendor/dompdf/dompdf/www/setup.php
```

