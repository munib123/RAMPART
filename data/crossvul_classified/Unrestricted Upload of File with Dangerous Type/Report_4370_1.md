# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in json
**Pair ID:** 4370_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4370_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "getkirby/cms",
  "description": "The Kirby 3 core",
  "version": "3.4.4",
  "license": "proprietary",
  "keywords": ["kirby", "cms", "core"],
  "homepage": "https://getkirby.com",
  "type": "kirby-cms",
  "authors": [
    {
      "name": "Kirby Team",
      "email": "support@getkirby.com",
      "homepage": "https://getkirby.com"
    }
  ],
  "support": {
    "email": "support@getkirby.com",
    "issues": "https://github.com/getkirby/kirby/issues",
    "forum": "https://forum.getkirby.com",
    "source": "https://github.com/getkirby/kirby"
  },
  "require": {
    "php": ">=7.2.0 <7.5.0",
    "ext-mbstring": "*",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "getkirby/cms",
   "description": "The Kirby 3 core",
-  "version": "3.4.4",
+  "version": "3.4.5",
   "license": "proprietary",
   "keywords": ["kirby", "cms", "core"],
   "homepage": "https://getkirby.com",
```
