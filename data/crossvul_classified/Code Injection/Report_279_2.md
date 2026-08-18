# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 279_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `279_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 9-49 of the vulnerable file.

 * @copyright Copyright (c) 2017 nystudio107
 */

/**
 * @author    nystudio107
 * @package   Seomatic
 * @since     3.0.0
 */

return [
    '*' => [
        'mainEntityOfPage'        => 'WebSite',
        'seoTitle'                => '',
        'siteNamePosition'        => 'before',
        'seoDescription'          => '',
        'seoKeywords'             => '',
        'seoImage'                => '',
        'seoImageWidth'           => '',
        'seoImageHeight'          => '',
        'seoImageDescription'     => '',
        'canonicalUrl'            => '{{ craft.app.request.pathInfo | striptags }}',
        'robots'                  => 'all',
        'ogType'                  => 'website',
        'ogTitle'                 => '{seomatic.meta.seoTitle}',
        'ogSiteNamePosition'      => 'none',
        'ogDescription'           => '{seomatic.meta.seoDescription}',
        'ogImage'                 => '{seomatic.meta.seoImage}',
        'ogImageWidth'            => '{seomatic.meta.seoImageWidth}',
        'ogImageHeight'           => '{seomatic.meta.seoImageHeight}',
        'ogImageDescription'      => '{seomatic.meta.seoImageDescription}',
        'twitterCard'             => 'summary',
        'twitterCreator'          => '{seomatic.site.twitterHandle}',
        'twitterTitle'            => '{seomatic.meta.seoTitle}',
        'twitterSiteNamePosition' => 'none',
        'twitterDescription'      => '{seomatic.meta.seoDescription}',
        'twitterImage'            => '{seomatic.meta.seoImage}',
        'twitterImageWidth'       => '{seomatic.meta.seoImageWidth}',
        'twitterImageHeight'      => '{seomatic.meta.seoImageHeight}',
        'twitterImageDescription' => '{seomatic.meta.seoImageDescription}',
    ],
];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
         'seoImageWidth'           => '',
         'seoImageHeight'          => '',
         'seoImageDescription'     => '',
-        'canonicalUrl'            => '{{ craft.app.request.pathInfo | striptags }}',
+        'canonicalUrl'            => '{seomatic.helper.safeCanonicalUrl()}',
         'robots'                  => 'all',
         'ogType'                  => 'website',
         'ogTitle'                 => '{seomatic.meta.seoTitle}',
```
