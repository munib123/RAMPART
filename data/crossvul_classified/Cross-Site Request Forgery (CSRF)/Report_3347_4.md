# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in json
**Pair ID:** 3347_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3347_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```json
Lines 67-88 of the vulnerable file.

            "reference": "407eb21da24150aad30bcd8cc0ee72963eac5e9d",
            "shasum": ""
        },
        "require": {
            "ext-openssl": "*"
        },
        "time": "2016-02-19T09:47:51+00:00",
        "type": "library",
        "installation-source": "dist",
        "autoload": {
            "classmap": [
                "src/"
            ]
        },
        "notification-url": "https://packagist.org/downloads/",
        "license": [
            "BSD-2-Clause"
        ],
        "description": "Library for U2F implementation",
        "homepage": "https://developers.yubico.com/php-u2flib-server"
    }
]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,5 +84,43 @@
         ],
         "description": "Library for U2F implementation",
         "homepage": "https://developers.yubico.com/php-u2flib-server"
+    },
+    {
+        "name": "owasp/csrf-protector-php",
+        "version": "dev-master",
+        "version_normalized": "9999999-dev",
+        "source": {
+            "type": "git",
+            "url": "https://github.com/mebjas/CSRF-Protector-PHP.git",
+            "reference": "aec0d6966992363a7192b2ae9fb0a9643e8fa26b"
+        },
+        "dist": {
+            "type": "zip",
+            "url": "https://api.github.com/repos/mebjas/CSRF-Protector-PHP/zipball/aec0d6966992363a7192b2ae9fb0a9643e8fa26b",
+            "reference": "aec0d6966992363a7192b2ae9fb0a9643e8fa26b",
+            "shasum": ""
+        },
+        "require-dev": {
+            "satooshi/php-coveralls": "~1.0"
+        },
+        "time": "2017-04-12T05:47:07+00:00",
+        "type": "library",
+        "installation-source": "source",
+        "autoload": {
+            "classmap": [
+                "libs/csrf/"
+            ]
+        },
+        "notification-url": "https://packagist.org/downloads/",
+        "license": [
+            "APACHE"
+        ],
+        "description": "CSRF protector php, a standalone php library for csrf mitigation in web applications. Easy to integrate in any php web app.",
+        "homepage": "https://github.com/mebjas/CSRF-Protector-PHP",
+        "keywords": [
+            "csrf",
+            "owasp",
+            "security"
+        ]
     }
 ]
```
