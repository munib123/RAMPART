# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2177_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2177_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
/**
 *
 * @file 		  find.php
 * @author 		  Nils Laumaillé
 * @version       2.1.19
 * @copyright 	  (c) 2009-2014 Nils Laumaillé
 * @licensing	  GNU AFFERO GPL 3.0
 * @link
 */

if (!isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1) {
    die('Hacking attempt...');
}

require_once $_SESSION['settings']['cpassman_dir'].'/sources/SplClassLoader.php';

// Build list of visible folders
$select_visible_folders_options = $select_visible_nonpersonal_folders_options = "";
if (isset($_SESSION['list_folders_limited']) && count($_SESSION['list_folders_limited']) > 0) {
    $list_folders_limited_keys = @array_keys($_SESSION['list_folders_limited']);
} else {
    $list_folders_limited_keys = array();
}
// list of items accessible but not in an allowed folder
if (isset($_SESSION['list_restricted_folders_for_items']) && count($_SESSION['list_restricted_folders_for_items']) > 0) {
    $list_restricted_folders_for_items_keys = @array_keys($_SESSION['list_restricted_folders_for_items']);
} else {
    $list_restricted_folders_for_items_keys = array();
}

//Build tree
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,8 +9,20 @@
  * @link
  */
 
-if (!isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1) {
+if (
+    !isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1 || 
+    !isset($_SESSION['user_id']) || empty($_SESSION['user_id']) || 
+    !isset($_SESSION['key']) || empty($_SESSION['key'])) 
+{
     die('Hacking attempt...');
+}
+
+/* do checks */
+require_once $_SESSION['settings']['cpassman_dir'].'/sources/checks.php';
+if (!checkUser($_SESSION['user_id'], $_SESSION['key'], curPage())) {
+    $_SESSION['error']['code'] = ERR_NOT_ALLOWED; //not allowed page
+    include 'error.php';
+    exit();
 }
 
 require_once $_SESSION['settings']['cpassman_dir'].'/sources/SplClassLoader.php';
```
