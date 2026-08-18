# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1609_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1609_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-30 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Validation callback.
 *
 * @package PhpMyAdmin-Setup
 */

/**
 * Core libraries.
 */
require './lib/common.inc.php';

$validators = array();
require './libraries/config/Validator.class.php';

header('Content-type: application/json');

$vids = explode(',', filter_input(INPUT_POST, 'id'));
$values = json_decode(filter_input(INPUT_POST, 'values'));
if (!($values instanceof stdClass)) {
    PMA_fatalError(__('Wrong data'));
}
$values = (array)$values;
$result = PMA_Validator::validate($GLOBALS['ConfigFile'], $vids, $values, true);
if ($result === false) {
    $result = 'Wrong data or no validation for ' . $vids;
}
echo $result !== true ? json_encode($result) : '';
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,8 +16,10 @@
 
 header('Content-type: application/json');
 
-$vids = explode(',', filter_input(INPUT_POST, 'id'));
-$values = json_decode(filter_input(INPUT_POST, 'values'));
+$ids = isset($_POST['id']) ? $_POST['id'] : null;
+$vids = explode(',', $ids);
+$vals = isset($_POST['values']) ? $_POST['values'] : null;
+$values = json_decode($vals);
 if (!($values instanceof stdClass)) {
     PMA_fatalError(__('Wrong data'));
 }
```
