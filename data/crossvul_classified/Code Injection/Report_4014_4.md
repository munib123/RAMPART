# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4014_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4014_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

/**
 * @author    nystudio107
 * @package   Seomatic
 * @since     3.0.0
 */
class UrlHelper extends CraftUrlHelper
{
    // Public Static Properties
    // =========================================================================

    // Public Static Methods
    // =========================================================================

    /**
     * @inheritDoc
     */
    public static function siteUrl(string $path = '', $params = null, string $scheme = null, int $siteId = null): string
    {
        $siteUrl = Seomatic::$settings->siteUrlOverride;
        if (!empty($siteUrl)) {
            return rtrim($siteUrl, '/').'/'.ltrim($path, '/');
        }

        return parent::siteUrl($path, $params, $scheme, $siteId);
    }

    /**
     * Return the page trigger and the value of the page trigger (null if it doesn't exist)
     *
     * @return array
     */
    public static function pageTriggerValue(): array
    {
        $pageTrigger = Craft::$app->getConfig()->getGeneral()->pageTrigger;
        if (!\is_string($pageTrigger) || $pageTrigger === '') {
            $pageTrigger = 'p';
        }
        // Is this query string-based pagination?
        if ($pageTrigger[0] === '?') {
            $pageTrigger = trim($pageTrigger, '?=');
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,7 @@
     {
         $siteUrl = Seomatic::$settings->siteUrlOverride;
         if (!empty($siteUrl)) {
+            $siteUrl = MetaValue::parseString($siteUrl);
             return rtrim($siteUrl, '/').'/'.ltrim($path, '/');
         }
 
```
