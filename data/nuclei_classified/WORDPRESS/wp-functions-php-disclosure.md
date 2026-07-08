# Vulnerability: functions.php Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-functions-php-disclosure.yaml`)

## Description
Detected a full server file path disclosure in the WordPress functions.php file. This exposure revealed sensitive directory information that could have aided attackers in further exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-admin/install.php
GET {{BaseURL}}/feed/
GET {{BaseURL}}/?feed=rss2
GET {{BaseURL}}/{{path}}
GET {{BaseURL}}/wp-content/themes/twentytwentyfour/functions.php
GET {{BaseURL}}/wp-content/themes/twentytwentythree/functions.php
GET {{BaseURL}}/wp-content/themes/twentytwentytwo/functions.php
GET {{BaseURL}}/wp-content/themes/twentytwentyone/functions.php
GET {{BaseURL}}/wp-content/themes/twentytwenty/functions.php
GET {{BaseURL}}/wp-content/themes/twentynineteen/functions.php
GET {{BaseURL}}/wp-content/themes/twentyeighteen/functions.php
GET {{BaseURL}}/wp-content/themes/twentyseventeen/functions.php
GET {{BaseURL}}/wp-content/themes/twentysixteen/functions.php
GET {{BaseURL}}/wp-content/themes/twentyfifteen/functions.php
GET {{BaseURL}}/wp-content/themes/twentyfourteen/functions.php
GET {{BaseURL}}/wp-content/themes/twentythirteen/functions.php
GET {{BaseURL}}/wp-content/themes/astra/functions.php
GET {{BaseURL}}/wp-content/themes/oceanwp/functions.php
GET {{BaseURL}}/wp-content/themes/generatepress/functions.php
GET {{BaseURL}}/wp-content/themes/kadence/functions.php
GET {{BaseURL}}/wp-content/themes/blocksy/functions.php
GET {{BaseURL}}/wp-content/themes/neve/functions.php
GET {{BaseURL}}/wp-content/themes/hello-elementor/functions.php
GET {{BaseURL}}/wp-content/themes/storefront/functions.php
GET {{BaseURL}}/wp-content/themes/divi/functions.php
GET {{BaseURL}}/wp-content/themes/avada/functions.php
GET {{BaseURL}}/wp-content/themes/twentytwenty-child/functions.php
GET {{BaseURL}}/wp-content/themes/astra-child/functions.php
GET {{BaseURL}}/wp-content/themes/generatepress-child/functions.php
```

