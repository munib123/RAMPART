# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1343_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1343_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 230-270 of the vulnerable file.

              $cmp[$cf_key][$fx] = date($dt_format,$cmp[$cf_key][$fx]);
            }
          }
        } 
      } // mega if
    }  // foraeach    
  }

  return (null != $cmp && count($cmp) > 0) ? $cmp : null; 
}



/**
 * 
 *
 */
function init_args() {
  $args = new stdClass();

  $args->req_id = isset($_REQUEST['requirement_id']) ? $_REQUEST['requirement_id'] : 0;
  $args->compare_selected_versions = isset($_REQUEST['compare_selected_versions']);
  $args->left_item_id = isset($_REQUEST['left_item_id']) ? intval($_REQUEST['left_item_id']) : -1;
  $args->right_item_id = isset($_REQUEST['right_item_id']) ? intval($_REQUEST['right_item_id']) :  -1;
    $args->tproject_id = isset($_SESSION['testprojectID']) ? $_SESSION['testprojectID'] : 0;

  $args->use_daisydiff = isset($_REQUEST['use_html_comp']);

  $diffEngineCfg = config_get("diffEngine");
  $args->context = null;
  if( !isset($_REQUEST['context_show_all']))  {
    $args->context = (isset($_REQUEST['context']) && is_numeric($_REQUEST['context'])) ? $_REQUEST['context'] : $diffEngineCfg->context;
  }
  
  return $args;
}

/**
 * 
 *
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -247,11 +247,12 @@
 function init_args() {
   $args = new stdClass();
 
-  $args->req_id = isset($_REQUEST['requirement_id']) ? $_REQUEST['requirement_id'] : 0;
+  $args->req_id = isset($_REQUEST['requirement_id']) ? intval($_REQUEST['requirement_id']) : 0;
+
   $args->compare_selected_versions = isset($_REQUEST['compare_selected_versions']);
   $args->left_item_id = isset($_REQUEST['left_item_id']) ? intval($_REQUEST['left_item_id']) : -1;
   $args->right_item_id = isset($_REQUEST['right_item_id']) ? intval($_REQUEST['right_item_id']) :  -1;
-    $args->tproject_id = isset($_SESSION['testprojectID']) ? $_SESSION['testprojectID'] : 0;
+    $args->tproject_id = isset($_SESSION['testprojectID']) ? intval($_SESSION['testprojectID']) : 0;
 
   $args->use_daisydiff = isset($_REQUEST['use_html_comp']);
 
```
