# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php

if (!defined('ABSPATH')) {
    die();
}

define('W3TC', true);
define('W3TC_VERSION', '0.9.4');
define('W3TC_POWERED_BY', 'W3 Total Cache/' . W3TC_VERSION);
define('W3TC_EMAIL', 'w3tc@w3-edge.com');
define('W3TC_TEXT_DOMAIN', 'w3-total-cache');
define('W3TC_PAYPAL_URL', 'https://www.paypal.com/cgi-bin/webscr');
define('W3TC_PAYPAL_BUSINESS', 'w3tc-team@w3-edge.com');
define('W3TC_LINK_URL', 'http://www.w3-edge.com/wordpress-plugins/');
define('W3TC_LINK_NAME', 'W3 EDGE, Optimization Products for WordPress');
define('W3TC_FEED_URL', 'http://feeds.feedburner.com/W3TOTALCACHE');
define('W3TC_NEWS_FEED_URL', 'http://feeds.feedburner.com/W3EDGE');
define('W3TC_README_URL', 'http://plugins.svn.wordpress.org/w3-total-cache/trunk/readme.txt');
define('W3TC_SUPPORT_US_TIMEOUT', 2592000);
define('W3TC_SUPPORT_REQUEST_URL', 'https://www.w3-edge.com/w3tc/support/');
define('W3TC_TRACK_URL', 'https://www.w3-edge.com/w3tc/track/');
define('W3TC_MAILLINGLIST_SIGNUP_URL', 'https://www.w3-edge.com/w3tc/emailsignup/');
define('NEWRELIC_SIGNUP_URL', 'http://bit.ly/w3tc-partner-newrelic-signup');
define('MAXCDN_SIGNUP_URL', 'http://bit.ly/w3tc-cdn-maxcdn-create-account');
define('MAXCDN_AUTHORIZE_URL', 'http://bit.ly/w3tc-cdn-maxcdn-authorize');
define('NETDNA_AUTHORIZE_URL', 'https://cp.netdna.com/i/w3tc');
// this is the URL our updater / license checker pings. This should be the URL of the site with EDD installed
if (!defined('EDD_W3EDGE_STORE_URL')) define('EDD_W3EDGE_STORE_URL', 'https://www.w3-edge.com/' );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
 }
 
 define('W3TC', true);
-define('W3TC_VERSION', '0.9.4');
+define('W3TC_VERSION', '0.9.4.1');
 define('W3TC_POWERED_BY', 'W3 Total Cache/' . W3TC_VERSION);
 define('W3TC_EMAIL', 'w3tc@w3-edge.com');
 define('W3TC_TEXT_DOMAIN', 'w3-total-cache');
```
