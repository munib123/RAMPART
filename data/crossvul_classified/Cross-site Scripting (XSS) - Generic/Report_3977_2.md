# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3977_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3977_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

                           'value' => $value];

        if ($action == 'insert') {
          tep_db_perform('currencies', $sql_data_array);
          $currency_id = tep_db_insert_id();
          
          $OSCOM_Hooks->call('currencies', 'insert');
          
        } elseif ($action == 'save') {
          tep_db_perform('currencies', $sql_data_array, 'update', "currencies_id = '" . (int)$currency_id . "'");
          
          $OSCOM_Hooks->call('currencies', 'save');
        }

        if (isset($_POST['default']) && ($_POST['default'] == 'on')) {
          tep_db_query("update configuration set configuration_value = '" . tep_db_input($code) . "' where configuration_key = 'DEFAULT_CURRENCY'");
        }
        
        $OSCOM_Hooks->call('currencies', 'saveinsert');        

        tep_redirect(tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $currency_id));
        break;
      case 'deleteconfirm':
        $currencies_id = tep_db_prepare_input($_GET['cID']);

        $currency_query = tep_db_query("select currencies_id from currencies where code = '" . DEFAULT_CURRENCY . "'");
        $currency = tep_db_fetch_array($currency_query);

        if ($currency['currencies_id'] == $currencies_id) {
          tep_db_query("update configuration set configuration_value = '' where configuration_key = 'DEFAULT_CURRENCY'");
        }

        tep_db_query("delete from currencies where currencies_id = '" . (int)$currencies_id . "'");
        
        $OSCOM_Hooks->call('currencies', 'deleteconfirm');

        tep_redirect(tep_href_link('currencies.php', 'page=' . $_GET['page']));
        break;
      case 'update':
        include_once('includes/languages/' . $language . '/modules/currencies/' . MODULE_ADMIN_CURRENCIES_INSTALLED);
        include_once('includes/modules/currencies/' . MODULE_ADMIN_CURRENCIES_INSTALLED);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,7 @@
         
         $OSCOM_Hooks->call('currencies', 'saveinsert');        
 
-        tep_redirect(tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $currency_id));
+        tep_redirect(tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $currency_id));
         break;
       case 'deleteconfirm':
         $currencies_id = tep_db_prepare_input($_GET['cID']);
@@ -76,7 +76,7 @@
         
         $OSCOM_Hooks->call('currencies', 'deleteconfirm');
 
-        tep_redirect(tep_href_link('currencies.php', 'page=' . $_GET['page']));
+        tep_redirect(tep_href_link('currencies.php', 'page=' . (int)$_GET['page']));
         break;
       case 'update':
         include_once('includes/languages/' . $language . '/modules/currencies/' . MODULE_ADMIN_CURRENCIES_INSTALLED);
@@ -205,9 +205,9 @@
               }
 
               if (isset($cInfo) && is_object($cInfo) && ($currency['currencies_id'] == $cInfo->currencies_id) ) {
-                echo '<tr class="table-active" onclick="document.location.href=\'' . tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=edit') . '\'">';
+                echo '<tr class="table-active" onclick="document.location.href=\'' . tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=edit') . '\'">';
               } else {
-                echo '<tr onclick="document.location.href=\'' . tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $currency['currencies_id']) . '\'">';
+                echo '<tr onclick="document.location.href=\'' . tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $currency['currencies_id']) . '\'">';
               }
 
               if (DEFAULT_CURRENCY == $currency['code']) {
@@ -218,7 +218,7 @@
               ?>
                 <td><?php echo $currency['code']; ?></td>
                 <td><?php echo number_format($currency['value'], 8); ?></td>
-                <td class="text-right"><?php if (isset($cInfo) && is_object($cInfo) && ($currency['currencies_id'] == $cInfo->currencies_id) ) { echo '<i class="fas fa-chevron-circle-right text-info"></i>'; } else { echo '<a href="' . tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $currency['currencies_id']) . '"><i class="fas fa-info-circle text-muted"></i></a>'; } ?></td>
+                <td class="text-right"><?php if (isset($cInfo) && is_object($cInfo) && ($currency['currencies_id'] == $cInfo->currencies_id) ) { echo '<i class="fas fa-chevron-circle-right text-info"></i>'; } else { echo '<a href="' . tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $currency['currencies_id']) . '"><i class="fas fa-info-circle text-muted"></i></a>'; } ?></td>
               </tr>
               <?php
             }
@@ -255,7 +255,7 @@
     case 'new':
       $heading[] = ['text' => TEXT_INFO_HEADING_NEW_CURRENCY];
 
-      $contents = ['form' => tep_draw_form('currencies', 'currencies.php', 'page=' . $_GET['page'] . (isset($cInfo) ? '&cID=' . $cInfo->currencies_id : '') . '&action=insert')];
+      $contents = ['form' => tep_draw_form('currencies', 'currencies.php', 'page=' . (int)$_GET['page'] . (isset($cInfo) ? '&cID=' . $cInfo->currencies_id : '') . '&action=insert')];
       $contents[] = ['text' => TEXT_INFO_INSERT_INTRO];
       $contents[] = ['text' => tep_draw_pull_down_menu('cs', $currency_select_array, '', 'onchange="updateForm();"')];
       $contents[] = ['text' => TEXT_INFO_CURRENCY_TITLE . '<br>' . tep_draw_input_field('title')];
@@ -272,7 +272,7 @@
     case 'edit':
       $heading[] = ['text' => TEXT_INFO_HEADING_EDIT_CURRENCY];
 
-      $contents = ['form' => tep_draw_form('currencies', 'currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=save')];
+      $contents = ['form' => tep_draw_form('currencies', 'currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=save')];
       $contents[] = ['text' => TEXT_INFO_EDIT_INTRO];
       $contents[] = ['text' => TEXT_INFO_CURRENCY_TITLE . '<br>' . tep_draw_input_field('title', $cInfo->title)];
       $contents[] = ['text' => TEXT_INFO_CURRENCY_CODE . '<br>' . tep_draw_input_field('code', $cInfo->code)];
@@ -283,20 +283,20 @@
       $contents[] = ['text' => TEXT_INFO_CURRENCY_DECIMAL_PLACES . '<br>' . tep_draw_input_field('decimal_places', $cInfo->decimal_places)];
       $contents[] = ['text' => TEXT_INFO_CURRENCY_VALUE . '<br>' . tep_draw_input_field('value', $cInfo->value)];
       if (DEFAULT_CURRENCY != $cInfo->code) $contents[] = ['text' => tep_draw_checkbox_field('default') . ' ' . TEXT_INFO_SET_AS_DEFAULT];
-      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_SAVE, 'fas fa-save', null, 'primary', null, 'btn-success xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id), null, null, 'btn-light')];
+      $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_SAVE, 'fas fa-save', null, 'primary', null, 'btn-success xxx text-white mr-2') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id), null, null, 'btn-light')];
       break;
     case 'delete':
       $heading[] = ['text' => TEXT_INFO_HEADING_DELETE_CURRENCY];
 
       $contents[] = ['text' => TEXT_INFO_DELETE_INTRO];
       $contents[] = ['class' => 'text-center text-uppercase font-weight-bold', 'text' => $cInfo->title];
-      $contents[] = ['class' => 'text-center', 'text' => (($remove_currency) ? tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=deleteconfirm'), null, null, 'btn-danger xxx text-white mr-2') : '') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id), null, null, 'btn-light')];
+      $contents[] = ['class' => 'text-center', 'text' => (($remove_currency) ? tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=deleteconfirm'), null, null, 'btn-danger xxx text-white mr-2') : '') . tep_draw_bootstrap_button(IMAGE_CANCEL, 'fas fa-times', tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id), null, null, 'btn-light')];
       break;
     default:
       if (is_object($cInfo)) {
         $heading[] = ['text' => $cInfo->title];
 
-        $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_EDIT, 'fas fa-cogs', tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=edit'), null, null, 'btn-warning mr-2') . tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', tep_href_link('currencies.php', 'page=' . $_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=delete'), null, null, 'btn-danger xxx text-white')];
+        $contents[] = ['class' => 'text-center', 'text' => tep_draw_bootstrap_button(IMAGE_EDIT, 'fas fa-cogs', tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=edit'), null, null, 'btn-warning mr-2') . tep_draw_bootstrap_button(IMAGE_DELETE, 'fas fa-trash', tep_href_link('currencies.php', 'page=' . (int)$_GET['page'] . '&cID=' . $cInfo->currencies_id . '&action=delete'), null, null, 'btn-danger xxx text-white')];
         $contents[] = ['text' => sprintf(TEXT_INFO_CURRENCY_TITLE, $cInfo->title)];
         $contents[] = ['text' => sprintf(TEXT_INFO_CURRENCY_CODE, $cInfo->code)];
... (diff truncated)
```
