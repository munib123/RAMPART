# Vulnerability: WordPress Plugin reCaptcha by BestWebSoft (google-captcha) - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-googlecaptcha-fpd.yaml`)

## Description
WordPress ManageWP Worker plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/google-captcha/includes/captcha-for-formidable.php
```

