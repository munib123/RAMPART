# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 3756_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
    "name": "zendframework/zend-feed",
    "description": "provides functionality for consuming RSS and Atom feeds",
    "license": "BSD-3-Clause",
    "keywords": [
        "zf2",
        "feed"
    ],
    "autoload": {
        "psr-0": {
            "Zend\\Feed": ""
        }
    },
    "target-dir": "Zend/Feed",
    "require": {
        "php": ">=5.3.3",
        "zendframework/zend-stdlib": "self.version"
    },
    "suggest": {
        "zendframework/zend-uri": "Zend\\Uri component",
        "zendframework/zend-validator": "Zend\\Validator component"
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
     "target-dir": "Zend/Feed",
     "require": {
         "php": ">=5.3.3",
+        "zendframework/zend-escaper": "self.version",
         "zendframework/zend-stdlib": "self.version"
     },
     "suggest": {
```
