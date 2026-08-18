# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1346_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1346_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 212-252 of the vulnerable file.

					}
				} 
			} // mega if
		}  // foraeach		
	}
	return count($cmp) > 0 ? $cmp : null;	
}



/**
 * 
 *
 */
function init_args()
{
	$_REQUEST=strings_stripSlashes($_REQUEST);
	

	$args = new stdClass();
	$args->req_spec_id = isset($_REQUEST['req_spec_id']) ? $_REQUEST['req_spec_id'] : 0;
	$args->doCompare = isset($_REQUEST['doCompare']) ? true : false;
	$args->left_item_id = isset($_REQUEST['left_item_id']) ? intval($_REQUEST['left_item_id']) : -1;
	$args->right_item_id = isset($_REQUEST['right_item_id']) ? intval($_REQUEST['right_item_id']) :  -1;
	$args->tproject_id = isset($_SESSION['testprojectID']) ? $_SESSION['testprojectID'] : 0;
	$args->useDaisyDiff = (isset($_REQUEST['diff_method']) && ($_REQUEST['diff_method'] == 'htmlCompare')) ? 1 : 0;
	

	$diffEngineCfg = config_get("diffEngine");
	$args->context = null;
	if( !isset($_REQUEST['context_show_all'])) 
	{
		$args->context = (isset($_REQUEST['context']) && is_numeric($_REQUEST['context'])) ? $_REQUEST['context'] : $diffEngineCfg->context;
	}
	
	return $args;
}

/**
 * 
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -229,13 +229,14 @@
 	
 
 	$args = new stdClass();
-	$args->req_spec_id = isset($_REQUEST['req_spec_id']) ? $_REQUEST['req_spec_id'] : 0;
+	$args->req_spec_id = isset($_REQUEST['req_spec_id']) ? intval($_REQUEST['req_spec_id']) : 0;
 	$args->doCompare = isset($_REQUEST['doCompare']) ? true : false;
 	$args->left_item_id = isset($_REQUEST['left_item_id']) ? intval($_REQUEST['left_item_id']) : -1;
 	$args->right_item_id = isset($_REQUEST['right_item_id']) ? intval($_REQUEST['right_item_id']) :  -1;
-	$args->tproject_id = isset($_SESSION['testprojectID']) ? $_SESSION['testprojectID'] : 0;
+	$args->tproject_id = isset($_SESSION['testprojectID']) ? intval($_SESSION['testprojectID']) : 0;
 	$args->useDaisyDiff = (isset($_REQUEST['diff_method']) && ($_REQUEST['diff_method'] == 'htmlCompare')) ? 1 : 0;
 	
+
 
 	$diffEngineCfg = config_get("diffEngine");
 	$args->context = null;
```
