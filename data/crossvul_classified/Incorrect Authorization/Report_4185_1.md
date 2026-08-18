# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4185_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4185_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 86-126 of the vulnerable file.

    {
        return [
            '^\..*'
        ];
    }

    /**
     * Extensions that are particularly benign.
     * This list can be customized with config:
     * - cms.fileDefinitions.defaultExtensions
     */
    protected function defaultExtensions()
    {
        return [
            'jpg',
            'jpeg',
            'bmp',
            'png',
            'webp',
            'gif',
            'svg',
            'js',
            'map',
            'ico',
            'css',
            'less',
            'scss',
            'ics',
            'odt',
            'doc',
            'docx',
            'ppt',
            'pptx',
            'pdf',
            'swf',
            'txt',
            'xml',
            'ods',
            'xls',
            'xlsx',
            'eot',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,6 @@
             'png',
             'webp',
             'gif',
-            'svg',
             'js',
             'map',
             'ico',
@@ -163,7 +162,6 @@
             'js',
             'woff',
             'woff2',
-            'svg',
             'ttf',
             'eot',
             'json',
```
