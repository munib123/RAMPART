# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5160_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5160_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 94-134 of the vulnerable file.

// default values
$GLOBALS['reload'] = false;

// Use to identify current cycle is executing
// a multiquery statement or stored routine
if (!isset($_SESSION['is_multi_query'])) {
    $_SESSION['is_multi_query'] = false;
}

$ajax_reload = array();
// Are we just executing plain query or sql file?
// (eg. non import, but query box/window run)
if (! empty($sql_query)) {

    // apply values for parameters
    if (! empty($_REQUEST['parameterized'])
        && ! empty($_REQUEST['parameters'])
        && is_array($_REQUEST['parameters'])) {
        $parameters = $_REQUEST['parameters'];
        foreach ($parameters as $parameter => $replacement) {
            $quoted = preg_quote($parameter);
            // making sure that :param does not apply values to :param1
            $sql_query = preg_replace(
                '/' . $quoted . '([^a-zA-Z0-9_])/',
                PMA\libraries\Util::sqlAddSlashes($replacement) . '${1}',
                $sql_query
            );
            // for parameters the appear at the end of the string
            $sql_query = preg_replace(
                '/' . $quoted . '$/',
                PMA\libraries\Util::sqlAddSlashes($replacement),
                $sql_query
            );
        }
    }

    // run SQL query
    $import_text = $sql_query;
    $import_type = 'query';
    $format = 'sql';
    $_SESSION['sql_from_query_box'] = true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,7 @@
         && is_array($_REQUEST['parameters'])) {
         $parameters = $_REQUEST['parameters'];
         foreach ($parameters as $parameter => $replacement) {
-            $quoted = preg_quote($parameter);
+            $quoted = preg_quote($parameter, '/');
             // making sure that :param does not apply values to :param1
             $sql_query = preg_replace(
                 '/' . $quoted . '([^a-zA-Z0-9_])/',
```
