# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 279_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `279_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php
/**
 * SEOmatic plugin for Craft CMS 3.x
 *
 * A turnkey SEO implementation for Craft CMS that is comprehensive, powerful,
 * and flexible
 *
 * @link      https://nystudio107.com
 * @copyright Copyright (c) 2017 nystudio107
 */

namespace nystudio107\seomatic\services;

use nystudio107\seomatic\Seomatic;
use nystudio107\seomatic\helpers\DynamicMeta as DynamicMetaHelper;
use nystudio107\seomatic\helpers\ImageTransform as ImageTransformHelper;
use nystudio107\seomatic\helpers\Schema as SchemaHelper;
use nystudio107\seomatic\helpers\Text as TextHelper;

use craft\base\Component;
use craft\elements\Asset;
use craft\elements\db\MatrixBlockQuery;
use craft\elements\db\TagQuery;
use craft\helpers\Template;
use craft\helpers\UrlHelper;
use craft\web\twig\variables\Paginate;

/**
 * @author    nystudio107
 * @package   Seomatic
 * @since     3.0.0
 */
class Helper extends Component
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,19 +11,22 @@
 
 namespace nystudio107\seomatic\services;
 
+use nystudio107\seomatic\helpers\UrlHelper;
 use nystudio107\seomatic\Seomatic;
 use nystudio107\seomatic\helpers\DynamicMeta as DynamicMetaHelper;
 use nystudio107\seomatic\helpers\ImageTransform as ImageTransformHelper;
 use nystudio107\seomatic\helpers\Schema as SchemaHelper;
 use nystudio107\seomatic\helpers\Text as TextHelper;
 
+use Craft;
 use craft\base\Component;
 use craft\elements\Asset;
 use craft\elements\db\MatrixBlockQuery;
 use craft\elements\db\TagQuery;
 use craft\helpers\Template;
-use craft\helpers\UrlHelper;
 use craft\web\twig\variables\Paginate;
+
+use yii\base\InvalidConfigException;
 
 /**
  * @author    nystudio107
@@ -39,8 +42,27 @@
     // =========================================================================
 
     /**
+     * Return the canonical URL for the request, with the query string stripped
+     *
+     * @return string
+     */
+    public static function safeCanonicalUrl(): string
+    {
+        $url = '';
+        try {
+            $url = Craft::$app->getRequest()->getPathInfo();
+        } catch (InvalidConfigException $e) {
+            Craft::error($e->getMessage(), __METHOD__);
+        }
+        $url = UrlHelper::stripQueryString($url);
+
+        return UrlHelper::absoluteUrlWithProtocol($url);
+    }
+
+    /**
      * Paginate based on the passed in Paginate variable as returned from the
-     * Twig {% paginate %} tag: https://docs.craftcms.com/v3/templating/tags/paginate.html#the-pageInfo-variable
+     * Twig {% paginate %} tag:
+     * https://docs.craftcms.com/v3/templating/tags/paginate.html#the-pageInfo-variable
      *
      * @param Paginate $pageInfo
      */
@@ -86,8 +108,8 @@
      * Return a list of localized URLs that are in the current site's group
      * The current URI is used if $uri is null. Similarly, the current site is
      * used if $siteId is null.
-     * The resulting array of arrays has `id`, `language`, `ogLanguage`, `hreflangLanguage`,
-     * and `url` as keys.
+     * The resulting array of arrays has `id`, `language`, `ogLanguage`,
+     * `hreflangLanguage`, and `url` as keys.
      *
      * @param string|null $uri
      * @param int|null    $siteId
@@ -131,6 +153,7 @@
             .$inlineStr
             .'/'
             .$fileName;
+
         return Template::raw(UrlHelper::siteUrl($seoFileLink));
     }
 
@@ -239,6 +262,30 @@
     }
 
     /**
+     * Return a flattened, indented menu of the given $path
+     *
+     * @param string $path
+     *
+     * @return array
+     */
+    public static function getTypeMenu($path): array
+    {
+        return SchemaHelper::getTypeMenu($path);
+    }
+
+    /**
+     * Return a single menu of schemas starting at $path
+     *
+     * @param string $path
+     *
+     * @return array
+     */
+    public static function getSingleTypeMenu($path): array
+    {
+        return SchemaHelper::getSingleTypeMenu($path);
+    }
+
+    /**
      * Transform the $asset for social media sites in $transformName and
      * optional $siteId
      *
@@ -282,28 +329,4 @@
     {
         return ImageTransformHelper::socialTransformHeight($asset, $transformName, $siteId);
     }
-
-    /**
-     * Return a flattened, indented menu of the given $path
-     *
-     * @param string $path
-     *
-     * @return array
-     */
-    public static function getTypeMenu($path): array
-    {
-        return SchemaHelper::getTypeMenu($path);
-    }
-
-    /**
-     * Return a single menu of schemas starting at $path
-     *
-     * @param string $path
-     *
-     * @return array
-     */
-    public static function getSingleTypeMenu($path): array
-    {
-        return SchemaHelper::getSingleTypeMenu($path);
-    }
 }
```
