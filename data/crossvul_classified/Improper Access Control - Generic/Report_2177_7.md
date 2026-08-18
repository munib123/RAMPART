# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2177_7
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2177_7`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
/**
 *
 * @file          folders.php
 * @author        Nils Laumaillé
 * @version       2.1.19
 * @copyright     (c) 2009-2014 Nils Laumaillé
 * @licensing     GNU AFFERO GPL 3.0
 * @link	      http://www.teampass.net
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

if (!isset($_SESSION['CPM']) || $_SESSION['CPM'] != 1) {
    die('Hacking attempt...');
}

require_once $_SESSION['settings']['cpassman_dir'].'/sources/SplClassLoader.php';

/* load help*/
require_once $_SESSION['settings']['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'_admin_help.php';

//Build tree
$tree = new SplClassLoader('Tree\NestedTree', $_SESSION['settings']['cpassman_dir'].'/includes/libraries');
$tree->register();
$tree = new Tree\NestedTree\NestedTree($pre.'nested_tree', 'id', 'parent_id', 'title');

/* Get full tree structure */
$tst = $tree->getDescendants();

/* Build list of all folders */
if ($_SESSION['is_admin'] == 1 || $_SESSION['settings']['can_create_root_folder'] == 1) {
    $folders_list = "\'0\':\'".$txt['root']."\'";
} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,8 +13,20 @@
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
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
@@ -89,7 +101,16 @@
 foreach ($tst as $t) {
     if (in_array($t->id, $_SESSION['groupes_visibles']) && !in_array($t->id, $_SESSION['personal_visible_groups'])) {
         // r?cup $t->parent_id
-        $data = $db->fetchRow("SELECT title FROM ".$pre."nested_tree WHERE id = ".$t->parent_id);
+        //$data = $db->fetchRow("SELECT title FROM ".$pre."nested_tree WHERE id = ".$t->parent_id);
+        $data = $db->queryGetRow(
+            "nested_tree",
+            array(
+                "title"
+            ),
+            array(
+                "id" => intval($t->parent_id)
+            )
+        );
         if ($t->nlevel == 1) {
             $data[0] = $txt['root'];
         }
@@ -105,48 +126,74 @@
             $ident .= "&nbsp;&nbsp;";
         }
         // Get some elements from DB concerning this node
-        $node_data = $db->fetchRow(
+        /*$node_data = $db->fetchRow(
             "SELECT m.valeur as valeur, n.renewal_period as renewal_period
             FROM ".$pre."misc as m,
             ".$pre."nested_tree as n
             WHERE m.type='complex'
             AND m.intitule = n.id
             AND m.intitule = ".$t->id
+        );*/
+        $node_data = $db->queryGetRow(
+            array(
+                "misc" => "m",
+                "nested_tree" => "n"
+            ),
+            array(
+                "m.valeur" => "valeur",
+                "n.renewal_period" => "renewal_period"
+            ),
+            array(
+                "m.type" => "complex",
+                "m.intitule" => intval(n.id),
+                "m.intitule" => intval($t->id)
+            )
         );
 
-        echo '<tr class="ligne0" id="row_'.$t->id.'">
-                        <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">'.$t->id.'</td>
-                        <td width="50%" onclick="open_edit_folder_dialog('.$t->id.')">
-                            '.$ident.'<span id="title_'.$t->id.'">'.$t->title.'</span>
-                        </td>
-                        <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
-                            <span id="complexite_'.$t->id.'">'.@$pwComplexity[$node_data[0]][1].'</span>
-                        </td>
-                        <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
-                            <span id="parent_'.$t->id.'">'.$data[0].'</span>
-                        </td>
-                        <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
-                            '.$t->nlevel.'
-                        </td>
-                        <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
-                            <span id="renewal_'.$t->id.'">'.$node_data[1].'</span>
-                        </td>
-                        <td align="center">
-                            <img src="includes/images/folder--minus.png" onclick="supprimer_groupe(\''.$t->id.'\')" style="cursor:pointer;" />
-                        </td>';
-
-        $data3 = $db->fetchRow("SELECT bloquer_creation,bloquer_modification FROM ".$pre."nested_tree WHERE id = ".$t->id);
         echo '
-                        <td align="center">
-                            <input type="checkbox" id="cb_droit_'.$t->id.'" onchange="Changer_Droit_Complexite(\''.$t->id.'\',\'creation\')"', isset($data3[0]) && $data3[0] == 1 ? 'checked' : '', ' />
-                        </td>
-                        <td align="center">
-                            <input type="checkbox" id="cb_droit_modif_'.$t->id.'" onchange="Changer_Droit_Complexite(\''.$t->id.'\',\'modification\')"', isset($data3[1]) && $data3[1] == 1 ? 'checked' : '', ' />
-                        </td>
-                        <td>
-                            <input type="hidden"  id="parent_id_'.$t->id.'" value="'.$t->parent_id.'" />
-                            <input type="hidden"  id="renewal_id_'.$t->id.'" value="'.$node_data[0].'" />
-                        </td>
+                <tr class="ligne0" id="row_'.$t->id.'">
+                    <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">'.$t->id.'</td>
+                    <td width="50%" onclick="open_edit_folder_dialog('.$t->id.')">
+                        '.$ident.'<span id="title_'.$t->id.'">'.$t->title.'</span>
+                    </td>
+                    <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
+                        <span id="complexite_'.$t->id.'">'.@$pwComplexity[$node_data[0]][1].'</span>
+                    </td>
+                    <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
+                        <span id="parent_'.$t->id.'">'.$data[0].'</span>
+                    </td>
+                    <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
+                        '.$t->nlevel.'
+                    </td>
+                    <td align="center" onclick="open_edit_folder_dialog('.$t->id.')">
+                        <span id="renewal_'.$t->id.'">'.$node_data[1].'</span>
+                    </td>
+                    <td align="center">
+                        <img src="includes/images/folder--minus.png" onclick="supprimer_groupe(\''.$t->id.'\')" style="cursor:pointer;" />
+                    </td>';
+
+        //$data3 = $db->fetchRow("SELECT bloquer_creation,bloquer_modification FROM ".$pre."nested_tree WHERE id = ".$t->id);
+        $data3 = $db->queryGetRow(
+            array(
+                "bloquer_creation",
+                "bloquer_modification"
+            ),
+            "nested_tree",
+            array(
+                "id" => intval($t->id)
+            )
+        );
+        echo '
+                    <td align="center">
+                        <input type="checkbox" id="cb_droit_'.$t->id.'" onchange="Changer_Droit_Complexite(\''.$t->id.'\',\'creation\')"', isset($data3[0]) && $data3[0] == 1 ? 'checked' : '', ' />
+                    </td>
+                    <td align="center">
+                        <input type="checkbox" id="cb_droit_modif_'.$t->id.'" onchange="Changer_Droit_Complexite(\''.$t->id.'\',\'modification\')"', isset($data3[1]) && $data3[1] == 1 ? 'checked' : '', ' />
+                    </td>
+                    <td>
+                        <input type="hidden"  id="parent_id_'.$t->id.'" value="'.$t->parent_id.'" />
+                        <input type="hidden"  id="renewal_id_'.$t->id.'" value="'.$node_data[0].'" />
+                    </td>
                 </tr>';
         array_push($arr_ids, $t->id);
         $x++;
```
