# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1347_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1347_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 159-199 of the vulnerable file.

}
$smarty = new TLSmarty();
$smarty->assign('gui',$gui);
$smarty->display($templateCfg->template_dir . $templateCfg->default_template);


/**
 * init_args
 * creates a sort of namespace
 *
 * @return  object with some REQUEST and SESSION values as members.
 */
function init_args()
{
  $_REQUEST = strings_stripSlashes($_REQUEST);

  // if any piece of context is missing => we will display nothing instead of crashing WORK TO BE DONE
  $args = new stdClass();
  $args->tplan_id = isset($_REQUEST['tplan_id']) ? $_REQUEST['tplan_id'] : $_SESSION['testplanID'];
  $args->tproject_id = isset($_REQUEST['tproject_id']) ? $_REQUEST['tproject_id'] : $_SESSION['testprojectID'];
  $args->tcase_id = isset($_REQUEST['tcase_id']) ? $_REQUEST['tcase_id'] : 0;
  $args->tcversion_id = isset($_REQUEST['tcversion_id']) ? $_REQUEST['tcversion_id'] : 0;
  return $args; 
}


/**
 * 
 *
 */
function initializeGui($argsObj)
{
  $guiObj = new stdClass();
  $guiObj->pageTitle='';
  $guiObj->tcaseIdentity='';
  $guiObj->mainDescription=lang_get('add_tcversion_to_plans');;
  $guiObj->tcase_id=$argsObj->tcase_id;
  $guiObj->tcversion_id=$argsObj->tcversion_id;
  $guiObj->can_do=false;
  $guiObj->item_sep=config_get('gui')->title_separator_2;
  $guiObj->cancelActionJS = 'location.href=fRoot+' . "'" . "lib/testcases/archiveData.php?" .
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,8 +176,17 @@
   $args = new stdClass();
   $args->tplan_id = isset($_REQUEST['tplan_id']) ? $_REQUEST['tplan_id'] : $_SESSION['testplanID'];
   $args->tproject_id = isset($_REQUEST['tproject_id']) ? $_REQUEST['tproject_id'] : $_SESSION['testprojectID'];
+  
+  $args->tproject_id = intval($args->tproject_id);
+  $args->tplan_id = intval($args->tplan_id);
+
+
   $args->tcase_id = isset($_REQUEST['tcase_id']) ? $_REQUEST['tcase_id'] : 0;
+  $args->tcase_id = intval($args->tcase_id);
+
   $args->tcversion_id = isset($_REQUEST['tcversion_id']) ? $_REQUEST['tcversion_id'] : 0;
+  $args->tcversion_id = intval($args->tcversion_id);
+
   return $args; 
 }
 
```
