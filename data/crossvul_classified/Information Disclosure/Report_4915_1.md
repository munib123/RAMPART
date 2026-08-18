# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4915_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4915_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Front controller for setup script
 *
 * @package PhpMyAdmin-Setup
 * @license http://www.gnu.org/licenses/gpl.html GNU GPL 2.0
 */

/**
 * Core libraries.
 */
require './lib/common.inc.php';

$page = isset($_GET['page']) ? $_GET['page'] : null;
$page = preg_replace('/[^a-z]/', '', $page);
if ($page === '') {
    $page = 'index';
}
if (!file_exists("./setup/frames/$page.inc.php")) {
    // it will happen only when entering URL by hand, we don't care for these cases
    PMA_fatalError(__('Wrong GET file attribute value'));
}

// Handle done action info
$action_done = isset($_GET['action_done']) ? $_GET['action_done'] : null;
$action_done = preg_replace('/[^a-z_]/', '', $action_done);

PMA_noCacheHeader();

?>
<!DOCTYPE HTML>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8" />
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,7 @@
  */
 require './lib/common.inc.php';
 
-$page = isset($_GET['page']) ? $_GET['page'] : null;
+$page = PMA_isValid($_GET['page'], 'scalar') ? $_GET['page'] : null;
 $page = preg_replace('/[^a-z]/', '', $page);
 if ($page === '') {
     $page = 'index';
@@ -23,7 +23,7 @@
 }
 
 // Handle done action info
-$action_done = isset($_GET['action_done']) ? $_GET['action_done'] : null;
+$action_done = PMA_isValid($_GET['action_done'], 'scalar') ? $_GET['action_done'] : null;
 $action_done = preg_replace('/[^a-z_]/', '', $action_done);
 
 PMA_noCacheHeader();
```
