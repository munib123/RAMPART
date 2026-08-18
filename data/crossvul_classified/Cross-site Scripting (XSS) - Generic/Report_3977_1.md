# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3977_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3977_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 24-64 of the vulnerable file.

        $countries_iso_code_3 = tep_db_prepare_input($_POST['countries_iso_code_3']);
        $address_format_id = tep_db_prepare_input($_POST['address_format_id']);

        tep_db_query("insert into countries (countries_name, countries_iso_code_2, countries_iso_code_3, address_format_id) values ('" . tep_db_input($countries_name) . "', '" . tep_db_input($countries_iso_code_2) . "', '" . tep_db_input($countries_iso_code_3) . "', '" . (int)$address_format_id . "')");
        
        $OSCOM_Hooks->call('countries', 'countriesActionInsert');

        tep_redirect(tep_href_link('countries.php'));
        break;
      case 'save':
        $countries_id = tep_db_prepare_input($_GET['cID']);
        $countries_name = tep_db_prepare_input($_POST['countries_name']);
        $countries_iso_code_2 = tep_db_prepare_input($_POST['countries_iso_code_2']);
        $countries_iso_code_3 = tep_db_prepare_input($_POST['countries_iso_code_3']);
        $address_format_id = tep_db_prepare_input($_POST['address_format_id']);

        tep_db_query("update countries set countries_name = '" . tep_db_input($countries_name) . "', countries_iso_code_2 = '" . tep_db_input($countries_iso_code_2) . "', countries_iso_code_3 = '" . tep_db_input($countries_iso_code_3) . "', address_format_id = '" . (int)$address_format_id . "' where countries_id = '" . (int)$countries_id . "'");
        
        $OSCOM_Hooks->call('countries', 'countriesActionSave');

        tep_redirect(tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $countries_id));
        break;
      case 'deleteconfirm':
        $countries_id = tep_db_prepare_input($_GET['cID']);

        tep_db_query("delete from countries where countries_id = '" . (int)$countries_id . "'");
        
        $OSCOM_Hooks->call('countries', 'countriesActionDelete');

        tep_redirect(tep_href_link('countries.php', 'page=' . $_GET['page']));
        break;
    }
  }
  
  $OSCOM_Hooks->call('countries', 'countriesPostAction');

  require('includes/template_top.php');
?>

  <div class="row">
    <div class="col">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,7 @@
         
         $OSCOM_Hooks->call('countries', 'countriesActionSave');
 
-        tep_redirect(tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $countries_id));
+        tep_redirect(tep_href_link('countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . $countries_id));
         break;
       case 'deleteconfirm':
         $countries_id = tep_db_prepare_input($_GET['cID']);
@@ -50,7 +50,7 @@
         
         $OSCOM_Hooks->call('countries', 'countriesActionDelete');
 
-        tep_redirect(tep_href_link('countries.php', 'page=' . $_GET['page']));
+        tep_redirect(tep_href_link('countries.php', 'page=' . (int)$_GET['page']));
         break;
     }
   }
@@ -98,15 +98,15 @@
               }
 
               if (isset($cInfo) && is_object($cInfo) && ($countries['countries_id'] == $cInfo->countries_id)) {
-                echo '<tr class="table-active" onclick="document.location.href=\'' . tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . (int)$cInfo->countries_id . '&action=edit') . '\'">';
+                echo '<tr class="table-active" onclick="document.location.href=\'' . tep_href_link('countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . (int)$cInfo->countries_id . '&action=edit') . '\'">';
               } else {
-                echo '<tr onclick="document.location.href=\'' . tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . (int)$countries['countries_id']) . '\'">';
+                echo '<tr onclick="document.location.href=\'' . tep_href_link('countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . (int)$countries['countries_id']) . '\'">';
               }
               ?>
                 <td><?php echo $countries['countries_name']; ?></td>
                 <td><?php echo $countries['countries_iso_code_2']; ?></td>
                 <td><?php echo $countries['countries_iso_code_3']; ?></td>
-                <td class="text-right"><?php if (isset($cInfo) && is_object($cInfo) && ($countries['countries_id'] == $cInfo->countries_id) ) { echo '<i class="fas fa-chevron-circle-right text-info"></i>'; } else { echo '<a href="' . tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $countries['countries_id']) . '"><i class="fas fa-info-circle text-muted"></i></a>'; } ?></td>
+                <td class="text-right"><?php if (isset($cInfo) && is_object($cInfo) && ($countries['countries_id'] == $cInfo->countries_id) ) { echo '<i class="fas fa-chevron-circle-right text-info"></i>'; } else { echo '<a href="' . tep_href_link('countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . $countries['countries_id']) . '"><i class="fas fa-info-circle text-muted"></i></a>'; } ?></td>
               </tr>
               <?php
             }
@@ -129,38 +129,38 @@
     case 'new':
       $heading[] = ['text' => TEXT_INFO_HEADING_NEW_COUNTRY];
 
-      $contents = ['form' => tep_draw_form('countries', 'countries.php', 'page=' . $_GET['page'] . '&action=insert')];
+      $contents = ['form' => tep_draw_form('countries', 'countries.php', 'page=' . (int)$_GET['page'] . '&action=insert')];
       $contents[] = ['text' => TEXT_INFO_INSERT_INTRO];
       $contents[] = ['text' => TEXT_INFO_COUNTRY_NAME . '<br>' . tep_draw_input_field('countries_name')];
       $contents[] = ['text' => TEXT_INFO_COUNTRY_CODE_2 . '<br>' . tep_draw_input_field('countries_iso_code_2')];
       $contents[] = ['text' => TEXT_INFO_COUNTRY_CODE_3 . '<br>' . tep_draw_input_field('countries_iso_code_3')];
       $contents[] = ['text' => TEXT_INFO_ADDRESS_FORMAT . '<br>' . tep_draw_pull_down_menu('address_format_id', tep_get_address_formats())];
-      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_SAVE, 'fas fa-save', null, 'primary', null, 'btn-success xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('countries.php', 'page=' . $_GET['page']), null, null, 'btn-light')];
+      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_SAVE, 'fas fa-save', null, 'primary', null, 'btn-success xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('countries.php', 'page=' . (int)$_GET['page']), null, null, 'btn-light')];
       break;
     case 'edit':
       $heading[] = ['text' => TEXT_INFO_HEADING_EDIT_COUNTRY];
 
-      $contents = ['form' => tep_draw_form('countries', 'countries.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->countries_id . '&action=save')];
+      $contents = ['form' => tep_draw_form('countries', 'countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->countries_id . '&action=save')];
       $contents[] = ['text' => TEXT_INFO_EDIT_INTRO];
       $contents[] = ['text' => TEXT_INFO_COUNTRY_NAME . '<br>' . tep_draw_input_field('countries_name', $cInfo->countries_name)];
       $contents[] = ['text' => TEXT_INFO_COUNTRY_CODE_2 . '<br>' . tep_draw_input_field('countries_iso_code_2', $cInfo->countries_iso_code_2)];
       $contents[] = ['text' => TEXT_INFO_COUNTRY_CODE_3 . '<br>' . tep_draw_input_field('countries_iso_code_3', $cInfo->countries_iso_code_3)];
       $contents[] = ['text' => TEXT_INFO_ADDRESS_FORMAT . '<br>' . tep_draw_pull_down_menu('address_format_id', tep_get_address_formats(), $cInfo->address_format_id)];
-      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_SAVE, 'fas fa-save', null, 'primary', null, 'btn-success xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->countries_id), null, null, 'btn-light')];
+      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_SAVE, 'fas fa-save', null, 'primary', null, 'btn-success xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->countries_id), null, null, 'btn-light')];
       break;
     case 'delete':
       $heading[] = ['text' => TEXT_INFO_HEADING_DELETE_COUNTRY];
 
-      $contents = ['form' => tep_draw_form('countries', 'countries.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->countries_id . '&action=deleteconfirm')];
+      $contents = ['form' => tep_draw_form('countries', 'countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->countries_id . '&action=deleteconfirm')];
       $contents[] = ['text' => TEXT_INFO_DELETE_INTRO];
       $contents[] = ['class' => 'text-center text-uppercase font-weight-bold', 'text' => $cInfo->countries_name];
-      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', null, 'primary', null, 'btn-danger xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->countries_id), null, null, 'btn-light')];
+      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', null, 'primary', null, 'btn-danger xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('countries.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->countries_id), null, null, 'btn-light')];
       break;
     default:
       if (is_object($cInfo)) {
         $heading[] = ['text' => $cInfo->countries_name];
 
-        $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_EDIT, 'fas fa-cogs', tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->countries_id . '&action=edit'), null, null, 'btn-warning mr-2') . tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', tep_href_link('countries.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->countries_id . '&action=delete'), null, null, 'btn-danger xxx text-white')];
... (diff truncated)
```
