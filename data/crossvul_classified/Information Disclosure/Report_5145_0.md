# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5145_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5145_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 9-31 of the vulnerable file.

/**
 * Core libraries.
 */
require './lib/common.inc.php';

$validators = array();
require './libraries/config/Validator.php';

PMA_headerJSON();

$ids = PMA_isValid($_POST['id'], 'scalar') ? $_POST['id'] : null;
$vids = explode(',', $ids);
$vals = PMA_isValid($_POST['values'], 'scalar') ? $_POST['values'] : null;
$values = json_decode($vals);
if (!($values instanceof stdClass)) {
    PMA_fatalError(__('Wrong data'));
}
$values = (array)$values;
$result = PMA\libraries\config\Validator::validate($GLOBALS['ConfigFile'], $vids, $values, true);
if ($result === false) {
    $result = 'Wrong data or no validation for ' . $vids;
}
echo $result !== true ? json_encode($result) : '';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,9 @@
 $values = (array)$values;
 $result = PMA\libraries\config\Validator::validate($GLOBALS['ConfigFile'], $vids, $values, true);
 if ($result === false) {
-    $result = 'Wrong data or no validation for ' . $vids;
+    $result = sprintf(
+        __('Wrong data or no validation for %s'),
+        implode(',', $vids)
+    );
 }
 echo $result !== true ? json_encode($result) : '';
```
