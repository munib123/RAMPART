# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in json
**Pair ID:** 3904_3
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3904_3`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```json
Lines 19-59 of the vulnerable file.

        "ext-iconv": "*",
        "ext-intl": "*",
        "ext-json": "*",
        "ext-mbstring": "*",
        "ext-mysqli": "*",
        "ext-simplexml": "*",
        "ext-zlib": "*",
        "blueimp/jquery-file-upload": "^10.2",
        "elvanto/litemoji": "^1.4 || ^2.0",
        "guzzlehttp/guzzle": "^6.5",
        "htmlawed/htmlawed": "^1.2",
        "iamcal/lib_autolink": "^1.7",
        "laminas/laminas-cache": "^2.8",
        "laminas/laminas-i18n": "^2.10",
        "laminas/laminas-mail": "^2.10",
        "laminas/laminas-mime": "^2.7",
        "laminas/laminas-serializer": "^2.8",
        "mexitek/phpcolors": "^0.4.0",
        "michelf/php-markdown": "^1.6",
        "monolog/monolog": "^2.0",
        "phpmailer/phpmailer": "^6.0",
        "psr/log": "^1.1",
        "psr/simple-cache": "^1.0",
        "ramsey/uuid": "^4.0",
        "rlanvin/php-rrule": "^2.1",
        "sabre/dav": "^4.0",
        "sabre/http": "^5.0",
        "sabre/uri": "^2.1",
        "sabre/vobject": "^4.1",
        "scssphp/scssphp": "^1.0",
        "sebastian/diff": "^3.0",
        "simplepie/simplepie": "^1.5",
        "symfony/console": "^4.4",
        "tecnickcom/tcpdf": "^6.2",
        "true/punycode": "^2.1",
        "wapmorgan/unified-archive": "^0.2.0"
    },
    "require-dev": {
        "ext-xml": "*",
        "atoum/atoum": "^3.4",
        "consolidation/robo": "^2.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
         "mexitek/phpcolors": "^0.4.0",
         "michelf/php-markdown": "^1.6",
         "monolog/monolog": "^2.0",
+        "paragonie/sodium_compat": "^1.13",
         "phpmailer/phpmailer": "^6.0",
         "psr/log": "^1.1",
         "psr/simple-cache": "^1.0",
@@ -66,13 +67,15 @@
         "sensiolabs/security-checker": "^6.0"
     },
     "replace": {
+        "paragonie/random_compat": "*",
         "symfony/polyfill-ctype": "*",
         "symfony/polyfill-intl-idn": "*",
         "symfony/polyfill-mbstring": "*",
         "symfony/polyfill-php72": "*"
     },
     "suggest": {
-        "ext-ldap": "Used to provide LDAP authentication and synchronization"
+        "ext-ldap": "Used to provide LDAP authentication and synchronization",
+        "ext-sodium": "Used to provide strong encryption for sensitive data in database"
     },
     "config": {
         "optimize-autoloader": true,
```
