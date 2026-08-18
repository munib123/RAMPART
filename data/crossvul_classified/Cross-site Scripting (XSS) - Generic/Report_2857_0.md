# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2857_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2857_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 165-206 of the vulnerable file.

            'md',
            'less',
            'sass',
            'scss'
        ];
    }

    /**
     * Extensions typically used as images.
     * This list can be customized with config:
     * - cms.fileDefinitions.imageExtensions
     */
    protected function imageExtensions()
    {
        return [
            'jpg',
            'jpeg',
            'bmp',
            'png',
            'webp',
            'gif',
            'svg'
        ];
    }

    /**
     * Extensions typically used as video files.
     * This list can be customized with config:
     * - cms.fileDefinitions.videoExtensions
     */
    protected function videoExtensions()
    {
        return [
            'mp4',
            'avi',
            'mov',
            'mpg',
            'mpeg',
            'mkv',
            'webm'
        ];
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,8 +182,7 @@
             'bmp',
             'png',
             'webp',
-            'gif',
-            'svg'
+            'gif'
         ];
     }
 
```
