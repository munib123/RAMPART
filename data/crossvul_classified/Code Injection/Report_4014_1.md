# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in json
**Pair ID:** 4014_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4014_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```json
Lines 1-25 of the vulnerable file.

{
    "name": "nystudio107/craft-seomatic",
    "description": "SEOmatic facilitates modern SEO best practices & implementation for Craft CMS 3. It is a turnkey SEO system that is comprehensive, powerful, and flexible.",
    "type": "craft-plugin",
    "version": "3.2.48",
    "keywords": [
        "craft",
        "cms",
        "craftcms",
        "craft-plugin",
        "seomatic",
        "seo",
        "json-ld",
        "meta",
        "tags",
        "sitemap",
        "twitter",
        "facebook"
    ],
    "support": {
        "docs": "https://nystudio107.com/plugins/seomatic/documentation",
        "issues": "https://nystudio107.com/plugins/seomatic/support"
    },
    "license": "proprietary",
    "authors": [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
     "name": "nystudio107/craft-seomatic",
     "description": "SEOmatic facilitates modern SEO best practices & implementation for Craft CMS 3. It is a turnkey SEO system that is comprehensive, powerful, and flexible.",
     "type": "craft-plugin",
-    "version": "3.2.48",
+    "version": "3.2.49",
     "keywords": [
         "craft",
         "cms",
```
