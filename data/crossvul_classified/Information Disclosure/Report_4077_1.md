# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4077_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4077_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 123-163 of the vulnerable file.

        'admin/(.*/)?package\.json$',
        'admin/(.*/)?bower\.json$',
        'admin/(.*/)?config\.rb$',
        'admin/themes/default/sass$',
        //'admin/themes/new\-theme/js$',
        //'admin/themes/new\-theme/scss$',
        'themes/_core$',
        'themes/classic/_dev',
        'themes/webpack\.config\.js$',
        'themes/package\.json$',
        'vendor\/[a-zA-Z0-0_-]+\/[a-zA-Z0-0_-]+\/[Tt]ests?$',
        'vendor/tecnickcom/tcpdf/examples$',
        'app/cache/..*$',
        '.idea',
        'tools/build$',
        'tools/foreignkeyGenerator$',
        '.*node_modules.*',
        '\.eslintignore$',
        '\.eslintrc\.js$',
        '\.php_cs\.dist$',
        '\.docker-compose\.yml$',
        'tools/assets$',
        '\.webpack$',
    ];

    /**
     * Contains all files and directories of the PrestaShop release.
     *
     * @var array
     */
    protected $filesList = [];

    /**
     * Absolute path of the temp PrestaShop release.
     *
     * @var string
     */
    protected $tempProjectPath;

    /**
     * Absolute path of the current user's PrestaShop (root path).
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,7 +140,7 @@
         '\.eslintignore$',
         '\.eslintrc\.js$',
         '\.php_cs\.dist$',
-        '\.docker-compose\.yml$',
+        'docker-compose\.yml$',
         'tools/assets$',
         '\.webpack$',
     ];
```
