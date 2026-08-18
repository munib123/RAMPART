# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4929_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4929_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 58-100 of the vulnerable file.

if (defined('SESSIONUPLOAD')) {
    // write sessionupload back into the loaded PMA session

    $sessionupload = unserialize(SESSIONUPLOAD);
    foreach ($sessionupload as $key => $value) {
        $_SESSION[$key] = $value;
    }

    // remove session upload data that are not set anymore
    foreach ($_SESSION as $key => $value) {
        if (mb_substr($key, 0, mb_strlen(UPLOAD_PREFIX))
            == UPLOAD_PREFIX
            && ! isset($sessionupload[$key])
        ) {
            unset($_SESSION[$key]);
        }
    }
}
 */

// AJAX requests can't be cached!
PMA_noCacheHeader();

// $_GET["message"] is used for asking for an import message
if (isset($_GET["message"]) && $_GET["message"]) {

    header('Content-type: text/html');

    // wait 0.3 sec before we check for $_SESSION variable,
    // which is set inside import.php
    usleep(300000);

    $maximumTime = ini_get('max_execution_time');
    $timestamp = time();
    // wait until message is available
    while ($_SESSION['Import_message']['message'] == null) {
        // close session before sleeping
        session_write_close();
        // sleep
        usleep(250000); // 0.25 sec
        // reopen session
        session_start();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,11 +75,11 @@
 }
  */
 
-// AJAX requests can't be cached!
-PMA_noCacheHeader();
-
 // $_GET["message"] is used for asking for an import message
 if (isset($_GET["message"]) && $_GET["message"]) {
+
+    // AJAX requests can't be cached!
+    PMA_noCacheHeader();
 
     header('Content-type: text/html');
 
```
