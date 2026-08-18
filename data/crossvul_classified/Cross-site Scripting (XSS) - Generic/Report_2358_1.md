# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2358_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2358_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * URL redirector to avoid leaking Referer with some sensitive information.
 *
 * @package PhpMyAdmin
 */

/**
 * Gets core libraries and defines some variables
 */
define('PMA_MINIMUM_COMMON', true);
require_once './libraries/common.inc.php';

if (! PMA_isValid($_GET['url'])
    || ! preg_match('/^https?:\/\/[^\n\r]*$/', $_GET['url'])
    || ! PMA_isAllowedDomain($_GET['url'])
) {
    header('Location: ' . $cfg['PmaAbsoluteUri']);
} else {
    // JavaScript redirection is necessary. Because if header() is used
    //  then web browser sometimes does not change the HTTP_REFERER
    //  field and so with old URL as Referer, token also goes to
    //  external site.
    echo "<script type='text/javascript'>
            window.onload=function(){
                window.location='" . htmlspecialchars($_GET['url']) . "';
            }
        </script>";
    // Display redirecting msg on screen.
    printf(__('Taking you to %s.'), htmlspecialchars($_GET['url']));
}
die();
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,10 @@
  */
 define('PMA_MINIMUM_COMMON', true);
 require_once './libraries/common.inc.php';
+/**
+ * JavaScript escaping.
+ */
+require_once './libraries/js_escape.lib.php';
 
 if (! PMA_isValid($_GET['url'])
     || ! preg_match('/^https?:\/\/[^\n\r]*$/', $_GET['url'])
@@ -24,7 +28,7 @@
     //  external site.
     echo "<script type='text/javascript'>
             window.onload=function(){
-                window.location='" . htmlspecialchars($_GET['url']) . "';
+                window.location='" . PMA_escapeJsString($_GET['url']) . "';
             }
         </script>";
     // Display redirecting msg on screen.
```
