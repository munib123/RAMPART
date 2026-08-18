# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2176_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2176_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php
/**
 *
 * @file          items.php
 * @author        Nils Laumaillé
 * @version       2.1.19
 * @copyright     (c) 2009-2014 Nils Laumaillé
 * @licensing     GNU AFFERO GPL 3.0
 * @link		  http://www.teampass.net
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

if (
    !isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1 || 
    !isset($_SESSION['user_id']) || empty($_SESSION['user_id']) || 
    !isset($_SESSION['key']) || empty($_SESSION['key'])) 
{
    die('Hacking attempt...');
}

/* do checks */
require_once $_SESSION['settings']['cpassman_dir'].'/sources/checks.php';
if (!checkUser($_SESSION['user_id'], $_SESSION['key'], curPage())) {
    $_SESSION['error']['code'] = ERR_NOT_ALLOWED; //not allowed page
    //include 'error.php';
    exit();
}

require_once $_SESSION['settings']['cpassman_dir'].'/sources/SplClassLoader.php';

//Build tree
$tree = new SplClassLoader('Tree\NestedTree', './includes/libraries');
$tree->register();
$tree = new Tree\NestedTree\NestedTree($pre.'nested_tree', 'id', 'parent_id', 'title');
$tree->rebuild();
$folders = $tree->getDescendants();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,9 +14,9 @@
  */
 
 if (
-    !isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1 || 
-    !isset($_SESSION['user_id']) || empty($_SESSION['user_id']) || 
-    !isset($_SESSION['key']) || empty($_SESSION['key'])) 
+    !isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1 ||
+    !isset($_SESSION['user_id']) || empty($_SESSION['user_id']) ||
+    !isset($_SESSION['key']) || empty($_SESSION['key']))
 {
     die('Hacking attempt...');
 }
@@ -74,11 +74,11 @@
 $selectVisibleFoldersOptions = $selectVisibleNonPersonalFoldersOptions = "";
 // Hidden things
 echo '
-<input type="hidden" name="hid_cat" id="hid_cat" value="', isset($_GET['group']) ? $_GET['group'] : "", '" />
+<input type="hidden" name="hid_cat" id="hid_cat" value="', isset($_GET['group']) ? htmlspecialchars($_GET['group']) : "", '" />
 <input type="hidden" id="complexite_groupe" />
 <input type="hidden" name="selected_items" id="selected_items" />
 <input type="hidden" name="input_liste_utilisateurs" id="input_liste_utilisateurs" value="'.$usersString.'" />
-<input type="hidden" name="input_list_roles" id="input_list_roles" value="'.htmlentities($listRoles, ENT_QUOTES, 'UTF-8').'" />
+<input type="hidden" name="input_list_roles" id="input_list_roles" value="'.htmlspecialchars(htmlentities($listRoles, ENT_QUOTES, 'UTF-8')).'" />
 <input type="hidden" id="bloquer_creation_complexite" />
 <input type="hidden" id="bloquer_modification_complexite" />
 <input type="hidden" id="error_detected" />
@@ -87,7 +87,7 @@
 <input type="hidden" id="richtext_on" value="1" />
 <input type="hidden" id="query_next_start" value="0" />
 <input type="hidden" id="display_categories" value="0" />
-<input type="hidden" id="nb_items_to_display_once" value="', isset($_SESSION['settings']['nb_items_by_query']) ? $_SESSION['settings']['nb_items_by_query'] : 'auto', '" />
+<input type="hidden" id="nb_items_to_display_once" value="', isset($_SESSION['settings']['nb_items_by_query']) ? htmlspecialchars($_SESSION['settings']['nb_items_by_query']) : 'auto', '" />
 <input type="hidden" id="user_is_read_only" value="', isset($_SESSION['user_read_only']) && $_SESSION['user_read_only'] == 1 ? '1' : '', '" />
 <input type="hidden" id="request_ongoing" />
 <input type="hidden" id="request_lastItem" />
@@ -118,7 +118,7 @@
     $firstGroup = "";
 }
 echo '
-<input type="hidden" name="jstree_group_selected" id="jstree_group_selected" value="'.$firstGroup.'" />';
+<input type="hidden" name="jstree_group_selected" id="jstree_group_selected" value="'.htmlspecialchars($firstGroup).'" />';
 
 echo '
 <div id="div_items">';
```
