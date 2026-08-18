# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 3756_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-18 of the vulnerable file.

{
    "name": "zendframework/zend-debug",
    "description": " ",
    "license": "BSD-3-Clause",
    "keywords": [
        "zf2",
        "debug"
    ],
    "autoload": {
        "psr-0": {
            "Zend\\Debug": ""
        }
    },
    "target-dir": "Zend/Debug",
    "require": {
        "php": ">=5.3.3"
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,10 @@
     },
     "target-dir": "Zend/Debug",
     "require": {
-        "php": ">=5.3.3"
+        "php": ">=5.3.3",
+        "zendframework/zend-escaper": "self.version"
+    },
+    "suggest": {
+        "ext/xdebug": "XDebug, for better backtrace output"
     }
 }
```
