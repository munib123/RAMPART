# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4929_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4929_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-37 of the vulnerable file.


/**
 * Loads the linter.
 */
require_once 'libraries/Linter.class.php';

/**
 * The SQL query to be analyzed.
 *
 * This does not need to be checked again XSS or MySQL injections because it is
 * never executed, just parsed.
 *
 * The client, which will recieve the JSON response will decode the message and
 * and any HTML fragments that are displayed to the user will be encoded anyway.
 *
 * @var string
 */
$sql_query = !empty($_POST['sql_query']) ? $_POST['sql_query'] : '';

// Disabling standard response.
$response = PMA_Response::getInstance();
$response->disable();

echo json_encode(PMA_Linter::lint($sql_query));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,8 @@
 $sql_query = !empty($_POST['sql_query']) ? $_POST['sql_query'] : '';
 
 // Disabling standard response.
-$response = PMA_Response::getInstance();
-$response->disable();
+PMA_Response::getInstance()->disable();
+
+PMA_headerJSON();
 
 echo json_encode(PMA_Linter::lint($sql_query));
```
