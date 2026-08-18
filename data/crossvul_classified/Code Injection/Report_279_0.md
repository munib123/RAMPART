# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 279_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `279_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 483-523 of the vulnerable file.

                try {
                    $url = $site->hasUrls ? UrlHelper::siteUrl($requestUri, $urlParams, null, $site->id)
                        : Craft::$app->getSites()->getPrimarySite()->baseUrl;
                } catch (SiteNotFoundException $e) {
                    $url = '';
                    Craft::error($e->getMessage(), __METHOD__);
                } catch (Exception $e) {
                    $url = '';
                    Craft::error($e->getMessage(), __METHOD__);
                }
            }
            $url = $url ?? '';
            if (!UrlHelper::isAbsoluteUrl($url)) {
                try {
                    $url = UrlHelper::siteUrl($url, $urlParams, null, $site->id);
                } catch (Exception $e) {
                    $url = '';
                    Craft::error($e->getMessage(), __METHOD__);
                }
            }
            $url = $url ?? '';
            $language = $site->language;
            $ogLanguage = str_replace('-', '_', $language);
            $hreflangLanguage = $language;
            $hreflangLanguage = strtolower($hreflangLanguage);
            $hreflangLanguage = str_replace('_', '-', $hreflangLanguage);
            $localizedUrls[] = [
                'id' => $site->id,
                'language' => $language,
                'ogLanguage' => $ogLanguage,
                'hreflangLanguage' => $hreflangLanguage,
                'url' => $url,
            ];
        }

        return $localizedUrls;
    }

    /**
     * Normalize the array of opening hours passed in
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -500,6 +500,12 @@
                     Craft::error($e->getMessage(), __METHOD__);
                 }
             }
+            // Strip any query string params, and make sure we have an absolute URL with protocol
+            if ($urlParams === null) {
+                $url = UrlHelper::stripQueryString($url);
+            }
+            $url = UrlHelper::absoluteUrlWithProtocol($url);
+
             $url = $url ?? '';
             $language = $site->language;
             $ogLanguage = str_replace('-', '_', $language);
```
