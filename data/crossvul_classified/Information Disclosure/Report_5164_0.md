# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5164_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5164_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 533-573 of the vulnerable file.

            $captcha_url = '';
        }
        /* Prevent against ClickJacking by disabling framing */
        if (! $GLOBALS['cfg']['AllowThirdPartyFraming']) {
            header(
                'X-Frame-Options: DENY'
            );
        }
        header(
            "Content-Security-Policy: default-src 'self' "
            . $captcha_url
            . $GLOBALS['cfg']['CSPAllow'] . ';'
            . "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            . $captcha_url
            . $GLOBALS['cfg']['CSPAllow'] . ';'
            . ";"
            . "style-src 'self' 'unsafe-inline' "
            . $captcha_url
            . $GLOBALS['cfg']['CSPAllow']
            . ";"
            . "img-src 'self' data: "
            . $GLOBALS['cfg']['CSPAllow']
            . $map_tile_urls
            . $captcha_url
            . ";"
        );
        header(
            "X-Content-Security-Policy: default-src 'self' "
            . $captcha_url
            . $GLOBALS['cfg']['CSPAllow'] . ';'
            . "options inline-script eval-script;"
            . "img-src 'self' data: "
            . $GLOBALS['cfg']['CSPAllow']
            . $map_tile_urls
            . $captcha_url
            . ";"
        );
        header(
            "X-WebKit-CSP: default-src 'self' "
            . $captcha_url
            . $GLOBALS['cfg']['CSPAllow'] . ';'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -550,6 +550,7 @@
             . $captcha_url
             . $GLOBALS['cfg']['CSPAllow']
             . ";"
+            . "referrer no-referrer;"
             . "img-src 'self' data: "
             . $GLOBALS['cfg']['CSPAllow']
             . $map_tile_urls
@@ -561,6 +562,7 @@
             . $captcha_url
             . $GLOBALS['cfg']['CSPAllow'] . ';'
             . "options inline-script eval-script;"
+            . "referrer no-referrer;"
             . "img-src 'self' data: "
             . $GLOBALS['cfg']['CSPAllow']
             . $map_tile_urls
@@ -575,6 +577,7 @@
             . $captcha_url
             . $GLOBALS['cfg']['CSPAllow']
             . " 'unsafe-inline' 'unsafe-eval';"
+            . "referrer no-referrer;"
             . "style-src 'self' 'unsafe-inline' "
             . $captcha_url
             . ';'
@@ -636,6 +639,7 @@
     private function _getMetaTags()
     {
         $retval  = '<meta charset="utf-8" />';
+        $retval .= '<meta name="referrer" content="none" />';
         $retval .= '<meta name="robots" content="noindex,nofollow" />';
         $retval .= '<meta http-equiv="X-UA-Compatible" content="IE=Edge">';
         if (! $GLOBALS['cfg']['AllowThirdPartyFraming']) {
```
