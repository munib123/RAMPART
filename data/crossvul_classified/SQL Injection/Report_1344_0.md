# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1344_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1344_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 68-108 of the vulnerable file.

		}
		
		// are there any changes? then display! if not, nothing to show here
		$msgKey = ($gui->diff[$key]['count'] > 0) ? 'num_changes' : 'no_changes';
    $gui->diff[$key]['message'] = sprintf($gui->labels[$msgKey], $gui->diff[$key]['heading'],
                                          $gui->diff[$key]['count']);
	}
} 
$smarty = new TLSmarty();
$smarty->assign('gui', $gui);
$smarty->display($templateCfg->template_dir . $templateCfg->default_template);


function init_args()
{
	$args = new stdClass();
  $args->use_daisydiff = isset($_REQUEST['use_html_comp']);
	

  $args->tcase_id = isset($_REQUEST['testcase_id']) ? $_REQUEST['testcase_id'] : 0;

  $key2set = array('compare_selected_versions' => 0,'version_left' => '','version_right' => '');
  foreach($key2set as $tk => $value)
  {
    $args->$tk = isset($_REQUEST[$tk]) ? $_REQUEST[$tk] : $value;
  } 
	
	
	if (isset($_REQUEST['context_show_all'])) 
  {
		$args->context = null;
	} 
  else 
  {
	  $diffEngineCfg = config_get("diffEngine");
  	$args->context = (isset($_REQUEST['context']) && is_numeric($_REQUEST['context'])) ? 
											$_REQUEST['context'] : $diffEngineCfg->context;	
	}
	
	return $args;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,8 @@
 	
 
   $args->tcase_id = isset($_REQUEST['testcase_id']) ? $_REQUEST['testcase_id'] : 0;
-
+  $args->tcase_id = intval($args->tcase_id);
+ 
   $key2set = array('compare_selected_versions' => 0,'version_left' => '','version_right' => '');
   foreach($key2set as $tk => $value)
   {
```
