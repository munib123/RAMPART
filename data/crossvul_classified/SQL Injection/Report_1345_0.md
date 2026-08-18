# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1345_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1345_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 71-110 of the vulnerable file.

{
	$gui->tplans[$value['id']] = $value['name'];
}

$smarty = new TLSmarty();
$smarty->assign('gui', $gui);
$smarty->display($templateCfg->template_dir . $templateCfg->default_template);



/**
 * init_args
 *
 */
function init_args()
{
	$_REQUEST = strings_stripSlashes($_REQUEST);
    
    $args = new stdClass();
    $args->user_id = $_SESSION['userID'];
    $args->tproject_id = $_SESSION['testprojectID'];
    $args->tproject_name = $_SESSION['testprojectName'];
    
    $args->tplan_id = isset($_REQUEST['tplan_id']) ? $_REQUEST['tplan_id'] : $_SESSION['testplanID'];
    
    $args->id = isset($_REQUEST['id']) ? $_REQUEST['id'] : null;
    $args->version_id = isset($_REQUEST['version_id']) ? $_REQUEST['version_id'] : 0;
    $args->level = isset($_REQUEST['level']) ? $_REQUEST['level'] : null;
    
    // Can be a list (string with , (comma) has item separator), 
    $args->keyword_id = isset($_REQUEST['keyword_id']) ? $_REQUEST['keyword_id'] : 0;

    return $args;  
}

function checkRights(&$db,&$user)
{
	return $user->hasRight($db,'testplan_planning');
}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,11 +88,12 @@
     
     $args = new stdClass();
     $args->user_id = $_SESSION['userID'];
-    $args->tproject_id = $_SESSION['testprojectID'];
+    $args->tproject_id = intval($_SESSION['testprojectID']);
     $args->tproject_name = $_SESSION['testprojectName'];
     
     $args->tplan_id = isset($_REQUEST['tplan_id']) ? $_REQUEST['tplan_id'] : $_SESSION['testplanID'];
-    
+    $args->tplan_id = intval($args->tplan_id);
+
     $args->id = isset($_REQUEST['id']) ? $_REQUEST['id'] : null;
     $args->version_id = isset($_REQUEST['version_id']) ? $_REQUEST['version_id'] : 0;
     $args->level = isset($_REQUEST['level']) ? $_REQUEST['level'] : null;
```
