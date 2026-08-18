# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 2832_6
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2832_6`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 209-249 of the vulnerable file.

                    <i id="items_list_loader" style="float:right;margin-right:5px;" class="fa fa-cog fa-spin mi-red hidden"></i>&nbsp;
                </div>
            </div>
            <div id="items_list"></div>
        </div>';
// Zone ITEM DETAIL
echo '
        <div id="item_details_ok">
            <input type="hidden" id="id_categorie" value="" />
            <input type="hidden" id="id_item" value="" />
            <input type="hidden" id="hid_anyone_can_modify" value="" />
            <div style="height:220px;overflow-y:auto;" id="item_details_scroll">
                <div id="handle" class="ui-resizable-handle ui-resizable-n"></div>';

echo'
                <div id="item_details_expired" style="display:none;background-color:white; margin:5px;">
                    <div class="ui-state-error ui-corner-all" style="padding:2px;">
                        <i class="fa fa-warning"></i>&nbsp;<b>'.$LANG['pw_is_expired_-_update_it'].'</b>
                    </div>
                </div>
                <table width="100%" id="item_details_table">';
// Line for LABEL
echo '
                <tr>
                    <td valign="top" class="td_title" colspan="2">
                        <div class="quick_menu2" style="float:left; margin-right: 5px;">
                            <ul class="quick_menu ui-menu">
                                <li><i class="fa fa-bars"></i>
                                    <ul class="menu_250">
                                        <li id="menu_button_copy_pw" class="copy_clipboard"><i class="fa fa-lock fa-fw"></i>&nbsp; '.$LANG['pw_copy_clipboard'].'</li>
                                        <li id="menu_button_copy_login" class="copy_clipboard"><i class="fa fa-user fa-fw"></i>&nbsp; '.$LANG['login_copy'].'</li>
                                        <li id="menu_button_show_pw" onclick="ShowPassword()"><i class="fa fa-eye fa-fw"></i>&nbsp; '.$LANG['mask_pw'].'</li>
                                        <li id="menu_button_copy_link" class="copy_clipboard"><i class="fa fa-link fa-fw"></i>&nbsp; '.$LANG['url_copy'].'</li>
                                        <li id="menu_button_history" onclick="OpenDialog(\'div_item_history\', \'false\')"><i class="fa fa-history fa-fw"></i>&nbsp; '.$LANG['history'].'</li>
                                        <li id="menu_button_share" onclick="OpenDialog(\'div_item_share\', \'false\')"><i class="fa fa-share fa-fw"></i>&nbsp; '.$LANG['share'].'</li>',
                                        (isset($SETTINGS['otv_is_enabled']) && $SETTINGS['otv_is_enabled'] == 1) ? '<li id="menu_button_otv" onclick="prepareOneTimeView()"><i class="fa fa-users fa-fw"></i>&nbsp; '.$LANG['one_time_item_view'].'</li>' : '', '
                                        ', isset($SETTINGS['enable_email_notification_on_item_shown']) && $SETTINGS['enable_email_notification_on_item_shown'] == 1 ? '
                                        <li id="menu_button_notify"><i class="fa fa-volume-up fa-fw"></i>&nbsp; '.$LANG['notify_me_on_change'].'</li>' : '', '
                                        ', isset($SETTINGS['enable_server_password_change']) && $SETTINGS['enable_server_password_change'] == 1 && isset($_SESSION['user_read_only']) && $_SESSION['user_read_only'] !== "1" ? '
                                        <li onclick="serverAutoChangePwd()"><i class="fa fa-server fa-fw"></i>&nbsp; '.$LANG['update_server_password'].'</li>' : '', '
                                        ', isset($SETTINGS['enable_suggestion']) && $SETTINGS['enable_suggestion'] == 1 ? '
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,11 +226,11 @@
                         <i class="fa fa-warning"></i>&nbsp;<b>'.$LANG['pw_is_expired_-_update_it'].'</b>
                     </div>
                 </div>
-                <table width="100%" id="item_details_table">';
+                <table width="100%" class="no-border" id="item_details_table">';
 // Line for LABEL
 echo '
                 <tr>
-                    <td valign="top" class="td_title" colspan="2">
+                    <td valign="top" class="td_title" width="120px" style="background-color:rgba(178, 178, 178, 0.13);">
                         <div class="quick_menu2" style="float:left; margin-right: 5px;">
                             <ul class="quick_menu ui-menu">
                                 <li><i class="fa fa-bars"></i>
@@ -252,7 +252,11 @@
                                 </li>
                             </ul>
                         </div>
-                        <div id="id_label" style="display:inline; margin:4px 0px 0px 120px; "></div>
+                    </td>
+                    <td valign="middle" style="background-color:rgba(178, 178, 178, 0.13);">
+                        <span id="id_label" style="font-weight:bold;"></span>
+                    </td>
+                    <td style="background-color:rgba(178, 178, 178, 0.13);">
                         <input type="hidden" id="hid_label" value="', isset($dataItem) ? htmlspecialchars($dataItem['label']) : '', '" />
                         <div style="float:right; font-family:arial; margin-right:5px;" id="item_viewed_x_times"></div>
 
@@ -266,7 +270,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title" width="180px">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['description'].' :</td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_desc" style="font-style:italic;display:inline;"></div><input type="hidden" id="hid_desc" value="', isset($dataItem) ? htmlspecialchars($dataItem['description']) : '', '" />
                     </td>
                 </tr>';
@@ -274,7 +278,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['pw'].' :<span id="button_quick_pw_copy" class="fa fa-paste fa-border fa-sm tip" style="cursor:pointer;display:none;float:right;margin-right:2px;" title="'.$LANG['item_menu_copy_pw'].'"></i></td>
-                    <td>
+                    <td colspan="2">
                         &nbsp;
                         <div id="id_pw" class="unhide_masked_data" style="float:left; cursor:pointer; width:300px;"></div>
                         <input type="hidden" id="hid_pw" value="" />
@@ -285,7 +289,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['index_login'].' :<span id="button_quick_login_copy" class="fa fa-paste fa-border fa-sm tip" style="cursor:pointer;display:none;float:right;margin-right:2px;" title="'.$LANG['item_menu_copy_login'].'"></span></td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_login" style="float:left;"></div>
                         <input type="hidden" id="hid_login" value="" />
                     </td>
@@ -294,7 +298,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['email'].' :</td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_email" style="display:inline;"></div><input type="hidden" id="hid_email" value="" />
                     </td>
                 </tr>';
@@ -302,7 +306,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['url'].' :</td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_url" style="display:inline;"></div><input type="hidden" id="hid_url" value="" />
                     </td>
                 </tr>';
@@ -310,7 +314,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['files_&_images'].' :</td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_files" style="display:inline;font-size:11px;"></div><input type="hidden" id="hid_files" />
                         <div id="dialog_files" style="display: none;">
 
@@ -321,7 +325,7 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['restricted_to'].' :</td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_restricted_to" style="display:inline;"></div><input type="hidden" id="hid_restricted_to" /><input type="hidden" id="hid_restricted_to_roles" />
                     </td>
                 </tr>';
@@ -329,34 +333,34 @@
 echo '
                 <tr>
                     <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['tags'].' :</td>
-                    <td>
+                    <td colspan="2">
                         <div id="id_tags" style="display:inline;"></div><input type="hidden" id="hid_tags" />
                     </td>
                 </tr>';
 // Line for KBs
 if (isset($SETTINGS['enable_kb']) && $SETTINGS['enable_kb'] == 1) {
     echo '
-                    <tr>
-                        <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['kbs'].' :</td>
-                        <td>
-                            <div id="id_kbs" style="display:inline;"></div><input type="hidden" id="hid_kbs" />
-                        </td>
-                    </tr>';
+                <tr>
+                    <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$LANG['kbs'].' :</td>
+                    <td colspan="2">
+                        <div id="id_kbs" style="display:inline;"></div><input type="hidden" id="hid_kbs" />
+                    </td>
+                </tr>';
 }
 // lines for FIELDS
 if (isset($SETTINGS['item_extra_fields']) && $SETTINGS['item_extra_fields'] == 1) {
     foreach ($_SESSION['item_fields'] as $elem) {
         $itemCatName = $elem[0];
         echo '
-                    <tr class="tr_fields hidden" id="tr_catfield_'.$elem[0].'">
-                        <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$elem[1].' :</td>
-                        <td></td>
-                    </tr>';
+                <tr class="tr_fields hidden" id="tr_catfield_'.$elem[0].'">
+                    <td valign="top" class="td_title">&nbsp;<i class="fa fa-angle-right"></i>&nbsp;'.$elem[1].' :</td>
+                    <td colspan="2"></td>
+                </tr>';
         foreach ($elem[2] as $field) {
             echo '
                     <tr class="tr_cf tr_fields hidden" id="cf_tr_'.$field[0].'">
                         <td valign="top" class="td_title">&nbsp;&nbsp;<i class="fa fa-caret-right"></i>&nbsp;<i>'.$field[1].'</i> :</td>
-                        <td>';
+                        <td colspan="2">';
             if ($field[3] === "masked") {
                 echo '
                             <div id="id_field_'.htmlspecialchars($field[0]).'_'.$elem[0].'" style="float:left; cursor:pointer; width:300px;" class="fields_div unhide_masked_data pointer"></div><input type="hidden" id="hid_field_'.htmlspecialchars($field[0]).'_'.$elem[0].'" class="fields" />';
@@ -778,7 +782,7 @@
     </div>';
 }
 echo '
-    <div style="display:none; padding:5px;" id="div_formulaire_edition_item_info" class="ui-state-default ui-corner-all"></div>
... (diff truncated)
```
