# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2177_8
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2177_8`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 56-96 of the vulnerable file.

    //Last items created block
    if (isset($_SESSION['settings']['show_last_items']) && $_SESSION['settings']['show_last_items'] == 1 && $_SESSION['user_admin'] != 1 && !empty($_SESSION['groupes_visibles_list'])) {
                    echo '
                    <div style="position:relative;float:right;margin-top:-25px;padding:4px;width:250px;" class="ui-state-highlight ui-corner-all">
                        <span class="ui-icon ui-icon-comment" style="float: left; margin-right: .3em;">&nbsp;</span>
                        <span style="font-weight:bold;margin-bottom:10px;">'.$txt['block_last_created'].'</span><br />';
                        $sql = "SELECT
                        i.label as label, i.id as id, i.id_tree as id_tree
                        FROM ".$pre."log_items l
                        INNER JOIN ".$pre."items i
                        WHERE l.action = 'at_creation'
                            AND l.id_item = i.id
                            AND i.id_tree IN (".$_SESSION['groupes_visibles_list'].")
                            AND i.perso = 0
                        ORDER BY l.date DESC
                        LIMIT 0,10
                        ";
        $cpt=1;
        $rows = $db->fetchAllArray($sql);
        foreach ($rows as $record) {
            $data = $db->fetchRow("SELECT COUNT(*) FROM ".$pre."log_items WHERE id_item = '".$record['id']."' AND action = 'at_delete'");
            if ($data[0] == 0) {
                echo '<span class="ui-icon ui-icon-tag" style="float: left; margin-right: .3em;">&nbsp;</span>
                <a href="#" onClick="javascript:$(\'#menu_action\').val(\'action\');window.location.href =\'index.php?page=items&amp;group='.$record['id_tree'].'&amp;id='.$record['id'].'\';" style="cursor:pointer;">'.stripslashes($record['label']).'</a><br />';
                if ($cpt==5) {
                    break;
                }
                $cpt++;
            }
        }
        echo '
                    </div>';
    }
    //ADMIN INFORMATION
    /*if ($_SESSION['user_admin'] == 1) {
        echo '
                    <div style="position:relative;float:right;margin-top:-25px;padding:4px;width:250px;" class="ui-state-highlight ui-corner-all">
                        <span class="ui-icon ui-icon-comment" style="float: left; margin-right: .3em;">&nbsp;</span>
                        <span style="font-weight:bold;margin-bottom:10px;">'.$txt['block_admin_info'].'</span><br />'.
                        $txt['admin_new1'].'
                    </div>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,14 @@
         $cpt=1;
         $rows = $db->fetchAllArray($sql);
         foreach ($rows as $record) {
-            $data = $db->fetchRow("SELECT COUNT(*) FROM ".$pre."log_items WHERE id_item = '".$record['id']."' AND action = 'at_delete'");
+            //$data = $db->fetchRow("SELECT COUNT(*) FROM ".$pre."log_items WHERE id_item = '".$record['id']."' AND action = 'at_delete'");
+            $data = $db->queryCount(
+                "log_items",
+                array(
+                    "id_item" => intval($record['id']),
+                    "action" => "at_delete"
+                )
+            );
             if ($data[0] == 0) {
                 echo '<span class="ui-icon ui-icon-tag" style="float: left; margin-right: .3em;">&nbsp;</span>
                 <a href="#" onClick="javascript:$(\'#menu_action\').val(\'action\');window.location.href =\'index.php?page=items&amp;group='.$record['id_tree'].'&amp;id='.$record['id'].'\';" style="cursor:pointer;">'.stripslashes($record['label']).'</a><br />';
```
