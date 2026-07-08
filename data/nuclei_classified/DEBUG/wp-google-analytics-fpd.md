# Vulnerability: WordPress Google Analytics - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-google-analytics-fpd.yaml`)

## Description
Detected WordPress Google Analytics Dashboard Plugin for WordPress by MonsterInsights, potentially revealing analytics data, file paths, and errors.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/google-analytics-for-wordpress/lite/includes/admin/connect.php
```

