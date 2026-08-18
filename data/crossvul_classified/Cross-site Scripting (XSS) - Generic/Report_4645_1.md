# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 4645_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4645_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 22-62 of the vulnerable file.

            "name": "Erik Tilt"
        },
        {
            "name": "Adrien Crivelli"
        }
    ],
    "scripts": {
        "check": [
            "php-cs-fixer fix --ansi --dry-run --diff",
            "phpcs",
            "phpunit --color=always"
        ],
        "fix": [
            "php-cs-fixer fix --ansi"
        ],
        "versions": [
            "phpcs --report-width=200 samples/ src/ tests/ --ignore=samples/Header.php --standard=PHPCompatibility --runtime-set testVersion 7.2- -n"
        ]
    },
    "require": {
        "php": "^7.2|^8.0",
        "ext-ctype": "*",
        "ext-dom": "*",
        "ext-gd": "*",
        "ext-iconv": "*",
        "ext-fileinfo": "*",
        "ext-libxml": "*",
        "ext-mbstring": "*",
        "ext-SimpleXML": "*",
        "ext-xml": "*",
        "ext-xmlreader": "*",
        "ext-xmlwriter": "*",
        "ext-zip": "*",
        "ext-zlib": "*",
        "maennchen/zipstream-php": "^2.1",
        "markbaker/complex": "^1.5|^2.0",
        "markbaker/matrix": "^1.2|^2.0",
        "psr/simple-cache": "^1.0",
        "psr/http-client": "^1.0",
        "psr/http-factory": "^1.0"
    },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
         ]
     },
     "require": {
-        "php": "^7.2|^8.0",
+        "php": "^7.2||^8.0",
         "ext-ctype": "*",
         "ext-dom": "*",
         "ext-gd": "*",
@@ -54,11 +54,12 @@
         "ext-zip": "*",
         "ext-zlib": "*",
         "maennchen/zipstream-php": "^2.1",
-        "markbaker/complex": "^1.5|^2.0",
-        "markbaker/matrix": "^1.2|^2.0",
+        "markbaker/complex": "^1.5||^2.0",
+        "markbaker/matrix": "^1.2||^2.0",
         "psr/simple-cache": "^1.0",
         "psr/http-client": "^1.0",
-        "psr/http-factory": "^1.0"
+        "psr/http-factory": "^1.0",
+        "voku/anti-xss": "^4.1"
     },
     "require-dev": {
         "dompdf/dompdf": "^0.8.5",
@@ -66,7 +67,7 @@
         "jpgraph/jpgraph": "^4.0",
         "mpdf/mpdf": "^8.0",
         "phpcompatibility/php-compatibility": "^9.3",
-        "phpunit/phpunit": "^8.5|^9.3",
+        "phpunit/phpunit": "^8.5||^9.3",
         "squizlabs/php_codesniffer": "^3.5",
         "tecnickcom/tcpdf": "^6.3"
     },
```
