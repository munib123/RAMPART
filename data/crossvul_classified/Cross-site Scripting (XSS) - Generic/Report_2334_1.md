# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2334_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2334_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 64-104 of the vulnerable file.

}

/**
 * Handle AJAX request for changing field information
 * (value,collation,operators,field values) in input form
 * @var post_params Object containing parameters for the POST request
 */

if (isset($_REQUEST['change_tbl_info']) && $_REQUEST['change_tbl_info'] == true) {
    $response = PMA_Response::getInstance();
    $field = $_REQUEST['field'];
    if ($field == 'pma_null') {
        $response->addJSON('field_type', '');
        $response->addJSON('field_collation', '');
        $response->addJSON('field_operators', '');
        $response->addJSON('field_value', '');
        exit;
    }
    $key = array_search($field, $table_search->getColumnNames());
    $properties = $table_search->getColumnProperties($_REQUEST['it'], $key);
    $response->addJSON('field_type', $properties['type']);
    $response->addJSON('field_collation', $properties['collation']);
    $response->addJSON('field_operators', $properties['func']);
    $response->addJSON('field_value', $properties['value']);
    exit;
}

// Gets some core libraries
require_once './libraries/tbl_common.inc.php';
$url_query .= '&amp;goto=tbl_select.php&amp;back=tbl_select.php';

// Gets tables informations
require_once './libraries/tbl_info.inc.php';

if (! isset($goto)) {
    $goto = $GLOBALS['cfg']['DefaultTabTable'];
}
// Defines the url to return to in case of error in the next sql statement
$err_url   = $goto . '?' . PMA_URL_getCommon($db, $table);

//Set default datalabel if not selected
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,7 +81,7 @@
     }
     $key = array_search($field, $table_search->getColumnNames());
     $properties = $table_search->getColumnProperties($_REQUEST['it'], $key);
-    $response->addJSON('field_type', $properties['type']);
+    $response->addJSON('field_type', htmlspecialchars($properties['type']));
     $response->addJSON('field_collation', $properties['collation']);
     $response->addJSON('field_operators', $properties['func']);
     $response->addJSON('field_value', $properties['value']);
```
