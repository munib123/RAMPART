# CrossVul Fix Pair: 7PK in php
**Pair ID:** 1764_1
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1764_1`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```php
Lines 15-37 of the vulnerable file.

 * JavaScript escaping.
 */
require_once './libraries/js_escape.lib.php';

if (! PMA_isValid($_REQUEST['url'])
    || ! preg_match('/^https?:\/\/[^\n\r]*$/', $_REQUEST['url'])
    || ! PMA_isAllowedDomain($_REQUEST['url'])
) {
    header('Location: ' . $cfg['PmaAbsoluteUri']);
} else {
    // JavaScript redirection is necessary. Because if header() is used
    //  then web browser sometimes does not change the HTTP_REFERER
    //  field and so with old URL as Referer, token also goes to
    //  external site.
    echo "<script type='text/javascript'>
            window.onload=function(){
                window.location='" . PMA_escapeJsString($_REQUEST['url']) . "';
            }
        </script>";
    // Display redirecting msg on screen.
    printf(__('Taking you to %s.'), htmlspecialchars($_REQUEST['url']));
}
die();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,7 @@
             }
         </script>";
     // Display redirecting msg on screen.
-    printf(__('Taking you to %s.'), htmlspecialchars($_REQUEST['url']));
+    // Do not display the value of $_REQUEST['url'] to avoid showing injected content
+    echo __('Taking you to the target site.');
 }
 die();
```
