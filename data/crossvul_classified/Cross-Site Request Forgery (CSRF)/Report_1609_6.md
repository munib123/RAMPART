# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1609_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1609_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

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

$page = filter_input(INPUT_GET, 'page');
$page = preg_replace('/[^a-z]/', '', $page);
if ($page === '') {
    $page = 'index';
}
if (!file_exists("./setup/frames/$page.inc.php")) {
    // it will happen only when entering URL by hand, we don't care for these cases
    PMA_fatalError(__('Wrong GET file attribute value'));
}

// Handle done action info
$action_done = filter_input(INPUT_GET, 'action_done');
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
 
-$page = filter_input(INPUT_GET, 'page');
+$page = isset($_GET['page']) ? $_GET['page'] : null;
 $page = preg_replace('/[^a-z]/', '', $page);
 if ($page === '') {
     $page = 'index';
@@ -23,7 +23,7 @@
 }
 
 // Handle done action info
-$action_done = filter_input(INPUT_GET, 'action_done');
+$action_done = isset($_GET['action_done']) ? $_GET['action_done'] : null;
 $action_done = preg_replace('/[^a-z_]/', '', $action_done);
 
 PMA_noCacheHeader();
```
