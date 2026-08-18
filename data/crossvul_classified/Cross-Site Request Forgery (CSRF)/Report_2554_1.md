# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2554_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2554_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 68-108 of the vulnerable file.

      $ret[] = $field;
      $disp = '<em>'.$disp.'</em>';
    }
    if ( isset($template_var) )
    {
      $template->assign( $template_var.strtoupper($field),
            '<a href="'.$url.$anchor.'" title="'.l10n('Sort order').'">'.$disp.'</a>'
         );
    }
  }
  return $ret;
}

if (!defined('PHPWG_ROOT_PATH')) die('Hacking attempt!');

include_once(PHPWG_ROOT_PATH.'admin/include/functions_permalinks.php');

$selected_cat = array();
if ( isset($_POST['set_permalink']) and $_POST['cat_id']>0 )
{
  $permalink = $_POST['permalink'];
  if ( empty($permalink) )
    delete_cat_permalink($_POST['cat_id'], isset($_POST['save']) );
  else
    set_cat_permalink($_POST['cat_id'], $permalink, isset($_POST['save']) );
  $selected_cat = array( $_POST['cat_id'] );
}
elseif ( isset($_GET['delete_permanent']) )
{
  $query = '
DELETE FROM '.OLD_PERMALINKS_TABLE.'
  WHERE permalink=\''.$_GET['delete_permanent'].'\'
  LIMIT 1';
  $result = pwg_query($query);
  if (pwg_db_changes($result)==0)
  {
    $page['errors'][] = l10n('Cannot delete the old permalink !');
  }
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,7 @@
 $selected_cat = array();
 if ( isset($_POST['set_permalink']) and $_POST['cat_id']>0 )
 {
+  check_pwg_token();
   $permalink = $_POST['permalink'];
   if ( empty($permalink) )
     delete_cat_permalink($_POST['cat_id'], isset($_POST['save']) );
@@ -94,6 +95,7 @@
 }
 elseif ( isset($_GET['delete_permanent']) )
 {
+  check_pwg_token();
   $query = '
 DELETE FROM '.OLD_PERMALINKS_TABLE.'
   WHERE permalink=\''.$_GET['delete_permanent'].'\'
@@ -125,6 +127,7 @@
 
 display_select_cat_wrapper( $query, $selected_cat, 'categories', false );
 
+$pwg_token = get_pwg_token();
 
 // --- generate display of active permalinks -----------------------------------
 $sort_by = parse_sort_variables(
@@ -178,12 +181,16 @@
   $row['U_DELETE'] =
       add_url_params(
         $url_del_base,
-        array( 'delete_permanent'=> $row['permalink'] )
+        array('delete_permanent'=> $row['permalink'],'pwg_token'=>$pwg_token)
       );
   $deleted_permalinks[] = $row;
 }
-$template->assign('deleted_permalinks', $deleted_permalinks);
-$template->assign('U_HELP', get_root_url().'admin/popuphelp.php?page=permalinks');
+
+$template->assign(array(
+  'PWG_TOKEN' => $pwg_token,
+  'U_HELP' => get_root_url().'admin/popuphelp.php?page=permalinks',
+  'deleted_permalinks' => $deleted_permalinks,
+  ));
 
 $template->assign_var_from_handle('ADMIN_CONTENT', 'permalinks');
 ?>
```
