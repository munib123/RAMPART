# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2178_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2178_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 79-121 of the vulnerable file.

<input type="hidden" name="selected_items" id="selected_items" />
<input type="hidden" name="input_liste_utilisateurs" id="input_liste_utilisateurs" value="'.$usersString.'" />
<input type="hidden" name="input_list_roles" id="input_list_roles" value="'.htmlspecialchars(htmlentities($listRoles, ENT_QUOTES, 'UTF-8')).'" />
<input type="hidden" id="bloquer_creation_complexite" />
<input type="hidden" id="bloquer_modification_complexite" />
<input type="hidden" id="error_detected" />
<input type="hidden" name="random_id" id="random_id" />
<input type="hidden" id="edit_wysiwyg_displayed" value="" />
<input type="hidden" id="richtext_on" value="1" />
<input type="hidden" id="query_next_start" value="0" />
<input type="hidden" id="display_categories" value="0" />
<input type="hidden" id="nb_items_to_display_once" value="', isset($_SESSION['settings']['nb_items_by_query']) ? htmlspecialchars($_SESSION['settings']['nb_items_by_query']) : 'auto', '" />
<input type="hidden" id="user_is_read_only" value="', isset($_SESSION['user_read_only']) && $_SESSION['user_read_only'] == 1 ? '1' : '', '" />
<input type="hidden" id="request_ongoing" />
<input type="hidden" id="request_lastItem" />
<input type="hidden" id="item_editable" />
<input type="hidden" id="timestamp_item_displayed" />
<input type="hidden" id="pf_selected" />';
// Hidden objects for Item search
if (isset($_GET['group']) && isset($_GET['id'])) {
    echo '<input type="hidden" name="open_folder" id="open_folder" value="'.$_GET['group'].'" />';
    echo '<input type="hidden" name="open_id" id="open_id" value="'.$_GET['id'].'" />';
    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="', in_array($_GET['group'], $_SESSION['personal_visible_groups']) ? '1' : '', '" />';
} elseif (isset($_GET['group']) && !isset($_GET['id'])) {
    echo '<input type="hidden" name="open_folder" id="open_folder" value="'.$_GET['group'].'" />';
    echo '<input type="hidden" name="open_id" id="open_id" value="" />';
    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="', in_array($_GET['group'], $_SESSION['personal_visible_groups']) ? '1' : '', '" />';
} else {
    echo '<input type="hidden" name="open_folder" id="open_folder" value="" />';
    echo '<input type="hidden" name="open_id" id="open_id" value="" />';
    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="" />';
}
// Is personal SK available
echo '
<input type="hidden" name="personal_sk_set" id="personal_sk_set" value="', isset($_SESSION['my_sk']) && !empty($_SESSION['my_sk']) ? '1':'0', '" />';
// define what group todisplay in Tree
if (isset($_COOKIE['jstree_select']) && !empty($_COOKIE['jstree_select'])) {
    $firstGroup = str_replace("#li_", "", $_COOKIE['jstree_select']);
} else {
    $firstGroup = "";
}
echo '
<input type="hidden" name="jstree_group_selected" id="jstree_group_selected" value="'.htmlspecialchars($firstGroup).'" />';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,13 +96,13 @@
 <input type="hidden" id="pf_selected" />';
 // Hidden objects for Item search
 if (isset($_GET['group']) && isset($_GET['id'])) {
-    echo '<input type="hidden" name="open_folder" id="open_folder" value="'.$_GET['group'].'" />';
-    echo '<input type="hidden" name="open_id" id="open_id" value="'.$_GET['id'].'" />';
-    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="', in_array($_GET['group'], $_SESSION['personal_visible_groups']) ? '1' : '', '" />';
+    echo '<input type="hidden" name="open_folder" id="open_folder" value="'.htmlspecialchars($_GET['group']).'" />';
+    echo '<input type="hidden" name="open_id" id="open_id" value="'.htmlspecialchars($_GET['id']).'" />';
+    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="', in_array(htmlspecialchars($_GET['group']), $_SESSION['personal_visible_groups']) ? '1' : '', '" />';
 } elseif (isset($_GET['group']) && !isset($_GET['id'])) {
-    echo '<input type="hidden" name="open_folder" id="open_folder" value="'.$_GET['group'].'" />';
+    echo '<input type="hidden" name="open_folder" id="open_folder" value="'.htmlspecialchars($_GET['group']).'" />';
     echo '<input type="hidden" name="open_id" id="open_id" value="" />';
-    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="', in_array($_GET['group'], $_SESSION['personal_visible_groups']) ? '1' : '', '" />';
+    echo '<input type="hidden" name="recherche_group_pf" id="recherche_group_pf" value="', in_array(htmlspecialchars($_GET['group']), $_SESSION['personal_visible_groups']) ? '1' : '', '" />';
 } else {
     echo '<input type="hidden" name="open_folder" id="open_folder" value="" />';
     echo '<input type="hidden" name="open_id" id="open_id" value="" />';
@@ -230,7 +230,7 @@
         	}
             // Prepare folder
             $folderTxt = '
-                    <li class="jstreeopen" id="li_'.$folder->id.'">';
+                    <li class="jstreeopen" id="li_'.$folder->id.'" title="ID ['.$folder->id.']">';
             if (in_array($folder->id, $_SESSION['groupes_visibles'])) {
                 $folderTxt .= '
                             <a id="fld_'.$folder->id.'" class="folder" onclick="ListerItems(\''.$folder->id.'\', \'\', 0);">'.$fldTitle.' (<span class="items_count" id="itcount_'.$folder->id.'">'.$itemsNb.'</span>';
@@ -358,7 +358,7 @@
                 <tr>
                     <td valign="top" class="td_title"><span class="ui-icon ui-icon-carat-1-e" style="float: left; margin-right: .3em;">&nbsp;</span>'.$txt['label'].' :</td>
                     <td>
-                        <input type="hidden" id="hid_label" value="', isset($dataItem) ? $dataItem['label'] : '', '" />
+                        <input type="hidden" id="hid_label" value="', isset($dataItem) ? htmlspecialchars($dataItem['label']) : '', '" />
                         <div id="id_label" style="display:inline;"></div>
                     </td>
                 </tr>';
@@ -367,7 +367,7 @@
                 <tr>
                     <td valign="top" class="td_title"><span class="ui-icon ui-icon-carat-1-e" style="float: left; margin-right: .3em;">&nbsp;</span>'.$txt['description'].' :</td>
                     <td>
-                        <div id="id_desc" style="font-style:italic;display:inline;"></div><input type="hidden" id="hid_desc" value="', isset($dataItem) ? $dataItem['description'] : '', '" />
+                        <div id="id_desc" style="font-style:italic;display:inline;"></div><input type="hidden" id="hid_desc" value="', isset($dataItem) ? htmlspecialchars($dataItem['description']) : '', '" />
                     </td>
                 </tr>';
 // Line for PW
@@ -455,7 +455,7 @@
                     <tr class="tr_fields itemCatName_'.$itemCatName.'">
                         <td valign="top" class="td_title">&nbsp;&nbsp;<span class="ui-icon ui-icon-carat-1-e" style="float: left; margin: 0 .3em 0 15px; font-size:9px;">&nbsp;</span><i>'.$field[1].'</i> :</td>
                         <td>
-                            <div id="id_field_'.$field[0].'" style="display:inline;" class="fields_div"></div><input type="hidden" id="hid_field_'.$field[0].'" class="fields" />
+                            <div id="id_field_'.$field[0].'" style="display:inline;" class="fields_div"></div><input type="hidden" id="hid_field_'.htmlspecialchars($field[0]).'" class="fields" />
                         </td>
                     </tr>';
         }
```
