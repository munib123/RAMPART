# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 279_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `279_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 185-225 of the vulnerable file.

     * @var string
     */
    public $twitterImageDescription;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function __construct(array $config = [])
    {
        // Unset any deprecated properties
        //unset($config['siteNamePosition']);
        parent::__construct($config);
    }

    /**
     * @inheritdoc
     */
    public function rules(): array
    {
        return [
            [
                [
                    'language',
                    'mainEntityOfPage',
                    'seoTitle',
                    'siteNamePosition',
                    'seoDescription',
                    'seoKeywords',
                    'seoImage',
                    'seoImageWidth',
                    'seoImageHeight',
                    'seoImageDescription',
                    'robots',
                    'ogType',
                    'ogTitle',
                    'ogSiteNamePosition',
                    'ogDescription',
                    'ogImage',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -197,6 +197,20 @@
         // Unset any deprecated properties
         //unset($config['siteNamePosition']);
         parent::__construct($config);
+    }
+
+    /**
+     * @inheritdoc
+     */
+    public function init()
+    {
+        parent::init();
+        // If we have potentially unsafe Twig code, strip it out
+        if (!empty($this->canonicalUrl)) {
+            if (strpos($this->canonicalUrl, 'craft.app.request.pathInfo') !== false) {
+                $this->canonicalUrl = '{seomatic.helper.safeCanonicalUrl()}';
+            }
+        }
     }
 
     /**
```
