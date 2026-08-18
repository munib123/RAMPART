# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1743_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1743_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 204-245 of the vulnerable file.

 * @param string $type The content type tp be sent
 * @param string $charset Optional character set to send with the header
 */
function MAX_commonSendContentTypeHeader($type = 'text/html', $charset = null)
{
    $header = 'Content-type: ' . $type;
    if (!empty($charset) && preg_match('/^[a-zA-Z0-9_-]+$/D', $charset)) {
        $header .= '; charset=' . $charset;
    }

    MAX_header($header);
}

/**
 * This function sends the anti-caching headers when called
 *
 */
function MAX_commonSetNoCacheHeaders()
{
    MAX_header('Pragma: no-cache');
    MAX_header('Cache-Control: private, max-age=0, no-cache');
    MAX_header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');

    // Also send default CORS headers
    MAX_header('Access-Control-Allow-Origin: *');
}

/**
 * Recursively add slashes to the values in an array.
*
 * @param array Input array.
 * @return array Output array with values slashed.
 */
function MAX_commonAddslashesRecursive($a)
{
    if (is_array($a)) {
        reset($a);
        while (list($k,$v) = each($a)) {
            $a[$k] = MAX_commonAddslashesRecursive($v);
        }
        reset ($a);
        return ($a);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,8 +221,8 @@
 function MAX_commonSetNoCacheHeaders()
 {
     MAX_header('Pragma: no-cache');
-    MAX_header('Cache-Control: private, max-age=0, no-cache');
-    MAX_header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
+    MAX_header('Cache-Control: no-cache, no-store, must-revalidate');
+    MAX_header('Expires: 0');
 
     // Also send default CORS headers
     MAX_header('Access-Control-Allow-Origin: *');
```
