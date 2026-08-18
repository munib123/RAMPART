# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 99-139 of the vulnerable file.

        <th>ID</th>
        <th>'.$LANG['group'].'</th>
        <th style="width:20px;">'.$LANG['nb_items'].'</th>
        <th>'.$LANG['complexity'].'</th>
        <th>'.$LANG['group_parent'].'</th>
        <th>'.$LANG['level'].'</th>
        <th style="width:20px;" title="'.htmlentities(strip_tags($LANG['group_pw_duration_tip']), ENT_QUOTES).'">'.$LANG['group_pw_duration'].'</th>
        <th style="width:20px;" title="'.htmlentities(strip_tags($LANG['auth_creation_without_complexity']), ENT_QUOTES).'"><i class="fa fa-legal fa-lg"></i></th>
        <th style="width:20px;" title="'.htmlentities(strip_tags($LANG['auth_modification_without_complexity']), ENT_QUOTES).'"><i class="fa fa-clock-o fa-lg"></i></th>
    </tr></thead>
    <tbody><tr id="placeholder_tr" style="display: none;"><td></td></tr>
    </tbody>
</table>
</div>';

/* Form Add a folder */
echo '
<div id="div_add_group" style="display:none;">
    <div id="addgroup_show_error" style="text-align:center;margin:2px;display:none;" class="ui-state-error ui-corner-all"></div>

    <label for="ajouter_groupe_titre" class="label_cpm">'.$LANG['group_title'].'</label>
    <input type="text" id="ajouter_groupe_titre" class="input_text text ui-widget-content ui-corner-all" />

    <label for="parent_id" class="label_cpm">'.addslashes($LANG['group_parent']).'</label>
    <select id="parent_id" class="input_text text ui-widget-content ui-corner-all">
        '.$droplist.'
    </select>

    <label for="new_rep_complexite" class="label_cpm">'.$LANG['complex_asked'].'</label>
    <select id="new_rep_complexite" class="input_text text ui-widget-content ui-corner-all">';
foreach ($SETTINGS_EXT['pwComplexity'] as $complex) {
    echo '<option value="'.$complex[0].'">'.$complex[1].'</option>';
}
echo '
    </select>

    <label for="add_node_renewal_period" class="label_cpm">'.$LANG['group_pw_duration'].'</label>
    <input type="text" id="add_node_renewal_period" value="0" class="input_text text ui-widget-content ui-corner-all" />

    <label for="folder_block_creation" class="">'.$LANG['auth_creation_without_complexity'].'</label>
    <select id="folder_block_creation" class="ui-widget-content ui-corner-all">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,7 +116,7 @@
 <div id="div_add_group" style="display:none;">
     <div id="addgroup_show_error" style="text-align:center;margin:2px;display:none;" class="ui-state-error ui-corner-all"></div>
 
-    <label for="ajouter_groupe_titre" class="label_cpm">'.$LANG['group_title'].'</label>
+    <label for="ajouter_groupe_titre" class="label_cpm">'.addslashes($LANG['group_title']).'</label>
     <input type="text" id="ajouter_groupe_titre" class="input_text text ui-widget-content ui-corner-all" />
 
     <label for="parent_id" class="label_cpm">'.addslashes($LANG['group_parent']).'</label>
@@ -124,7 +124,7 @@
         '.$droplist.'
     </select>
 
-    <label for="new_rep_complexite" class="label_cpm">'.$LANG['complex_asked'].'</label>
+    <label for="new_rep_complexite" class="label_cpm">'.addslashes($LANG['complex_asked']).'</label>
     <select id="new_rep_complexite" class="input_text text ui-widget-content ui-corner-all">';
 foreach ($SETTINGS_EXT['pwComplexity'] as $complex) {
     echo '<option value="'.$complex[0].'">'.$complex[1].'</option>';
@@ -132,17 +132,26 @@
 echo '
     </select>
 
-    <label for="add_node_renewal_period" class="label_cpm">'.$LANG['group_pw_duration'].'</label>
+    <span id="span_new_rep_roles">
+    <label for="new_rep_roles" class="label_cpm">'.addslashes($LANG['access_level_for_roles']).'</label>
+    <select id="new_rep_roles" class="input_text text ui-widget-content ui-corner-all">
+        <option value="">'.$LANG['no_access'].'</option>
+        <option value="R">'.$LANG['read'].'</option>
+        <option value="W">'.$LANG['write'].'</option>
+    </select>
+    </span>
+
+    <label for="add_node_renewal_period" class="label_cpm">'.addslashes($LANG['group_pw_duration']).'</label>
     <input type="text" id="add_node_renewal_period" value="0" class="input_text text ui-widget-content ui-corner-all" />
 
-    <label for="folder_block_creation" class="">'.$LANG['auth_creation_without_complexity'].'</label>
+    <label for="folder_block_creation" class="">'.addslashes($LANG['auth_creation_without_complexity']).'</label>
     <select id="folder_block_creation" class="ui-widget-content ui-corner-all">
         <option value="0">'.$LANG['no'].'</option>
         <option value="1">'.$LANG['yes'].'</option>
     </select>
 
     <div style="margin-top:10px;">
-        <label for="folder_block_modif">'.$LANG['auth_modification_without_complexity'].'</label>
+        <label for="folder_block_modif">'.addslashes($LANG['auth_modification_without_complexity']).'</label>
         <select id="folder_block_modif" class="ui-widget-content ui-corner-all">
             <option value="0">'.$LANG['no'].'</option>
             <option value="1">'.$LANG['yes'].'</option>
```
