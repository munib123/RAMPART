# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4327_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4327_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 26-66 of the vulnerable file.

    {
        // Set root URL
        $appUrl = config('app.url');
        if ($appUrl) {
            $isHttps = (strpos($appUrl, 'https://') === 0);
            URL::forceRootUrl($appUrl);
            URL::forceScheme($isHttps ? 'https' : 'http');
        }

        // Custom validation methods
        Validator::extend('image_extension', function ($attribute, $value, $parameters, $validator) {
            $validImageExtensions = ['png', 'jpg', 'jpeg', 'gif', 'webp'];
            return in_array(strtolower($value->getClientOriginalExtension()), $validImageExtensions);
        });

        Validator::extend('no_double_extension', function ($attribute, $value, $parameters, $validator) {
            $uploadName = $value->getClientOriginalName();
            return substr_count($uploadName, '.') < 2;
        });

        // Custom blade view directives
        Blade::directive('icon', function ($expression) {
            return "<?php echo icon($expression); ?>";
        });

        Blade::directive('exposeTranslations', function ($expression) {
            return "<?php \$__env->startPush('translations'); ?>" .
                "<?php foreach({$expression} as \$key): ?>" .
                '<meta name="translation" key="<?php echo e($key); ?>" value="<?php echo e(trans($key)); ?>">' . "\n" .
                "<?php endforeach; ?>" .
                '<?php $__env->stopPush(); ?>';
        });

        // Allow longer string lengths after upgrade to utf8mb4
        Schema::defaultStringLength(191);

        // Set morph-map due to namespace changes
        Relation::morphMap([
            'BookStack\\Bookshelf' => Bookshelf::class,
            'BookStack\\Book' => Book::class,
            'BookStack\\Chapter' => Chapter::class,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,13 @@
             return substr_count($uploadName, '.') < 2;
         });
 
+        Validator::extend('safe_url', function ($attribute, $value, $parameters, $validator) {
+            $cleanLinkName = strtolower(trim($value));
+            $isJs = strpos($cleanLinkName, 'javascript:') === 0;
+            $isData = strpos($cleanLinkName, 'data:') === 0;
+            return !$isJs && !$isData;
+        });
+
         // Custom blade view directives
         Blade::directive('icon', function ($expression) {
             return "<?php echo icon($expression); ?>";
```
