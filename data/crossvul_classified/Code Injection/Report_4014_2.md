# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4014_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4014_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 63-103 of the vulnerable file.

     */
    const EVENT_ADD_DYNAMIC_META = 'addDynamicMeta';

    // Static Methods
    // =========================================================================

    /**
     * Return a sanitized URL with the query string stripped
     *
     * @param string $url
     * @param bool $checkStatus
     *
     * @return string
     */
    public static function sanitizeUrl(string $url, bool $checkStatus = true): string
    {
        // Remove the query string
        $url = UrlHelper::stripQueryString($url);
        // HTML decode the entities, then strip out any tags
        $url = html_entity_decode($url, ENT_NOQUOTES, 'UTF-8');
        $url = strip_tags($url);

        // If this is a >= 400 status code, set the canonical URL to nothing
        if ($checkStatus && Craft::$app->getResponse()->statusCode >= 400) {
            $url = '';
        }
        // Remove any Twig tags that somehow are present in the incoming URL
        /** @noinspection CallableParameterUseCaseInTypeContextInspection */
        $result = preg_replace('/{.*}/', '', $url);
        if (!empty($result) && $result) {
            $url = $result;
        }

        return UrlHelper::absoluteUrlWithProtocol($url);
    }

    /**
     * Paginate based on the passed in Paginate variable as returned from the
     * Twig {% paginate %} tag:
     * https://docs.craftcms.com/v3/templating/tags/paginate.html#the-pageInfo-variable
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,6 +80,7 @@
         $url = UrlHelper::stripQueryString($url);
         // HTML decode the entities, then strip out any tags
         $url = html_entity_decode($url, ENT_NOQUOTES, 'UTF-8');
+        $url = urldecode($url);
         $url = strip_tags($url);
 
         // If this is a >= 400 status code, set the canonical URL to nothing
@@ -647,6 +648,7 @@
             $url = UrlHelper::absoluteUrlWithProtocol($url);
 
             $url = $url ?? '';
+            $url = self::sanitizeUrl($url);
             $language = $site->language;
             $ogLanguage = LocalizationHelper::normalizeOgLocaleLanguage($language);
             $hreflangLanguage = $language;
```
