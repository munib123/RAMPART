# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 3756_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 3-26 of the vulnerable file.

    "description": "component for general purpose logging",
    "license": "BSD-3-Clause",
    "keywords": [
        "zf2",
        "log",
        "logging"
    ],
    "autoload": {
        "psr-0": {
            "Zend\\Log": ""
        }
    },
    "target-dir": "Zend/Log",
    "require": {
        "php": ">=5.3.3",
        "zendframework/zend-stdlib": "self.version"
    },
    "suggest": {
        "ext-mongo": "*",
        "zendframework/zend-db": "Zend\\Db component",
        "zendframework/zend-mail": "Zend\\Mail component",
        "zendframework/zend-validator": "Zend\\Validator component"
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
     "suggest": {
         "ext-mongo": "*",
         "zendframework/zend-db": "Zend\\Db component",
+        "zendframework/zend-escaper": "Zend\\Escaper component, for use in the XML formatter",
         "zendframework/zend-mail": "Zend\\Mail component",
         "zendframework/zend-validator": "Zend\\Validator component"
     }
```
