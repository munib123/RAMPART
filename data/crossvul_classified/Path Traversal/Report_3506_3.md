# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3506_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3506_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 32-73 of the vulnerable file.

/**
 * requires string_api
 */
require_once( 'string_api.php' );
/**
 * requires date_api
 */
require_once( 'date_api.php' );
/**
 * requires icon_api
 */
require_once( 'icon_api.php' );

$t_filter = current_user_get_bug_filter();
if( $t_filter === false ) {
	$t_filter = filter_get_default();
}

$t_sort = $t_filter['sort'];
$t_dir = $t_filter['dir'];

$t_checkboxes_exist = false;

$t_icon_path = config_get( 'icon_path' );
$t_update_bug_threshold = config_get( 'update_bug_threshold' );
$t_bug_resolved_status_threshold = config_get( 'bug_resolved_status_threshold' );
$t_hide_status_default = config_get( 'hide_status_default' );
$t_default_show_changed = config_get( 'default_show_changed' );

$c_filter['assigned'] = array(
	FILTER_PROPERTY_CATEGORY => Array(
		'0' => META_FILTER_ANY,
	),
	FILTER_PROPERTY_SEVERITY_ID => Array(
		'0' => META_FILTER_ANY,
	),
	FILTER_PROPERTY_STATUS_ID => Array(
		'0' => META_FILTER_ANY,
	),
	FILTER_PROPERTY_HIGHLIGHT_CHANGED => $t_default_show_changed,
	FILTER_PROPERTY_REPORTER_ID => Array(
		'0' => META_FILTER_ANY,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,8 +50,6 @@
 $t_sort = $t_filter['sort'];
 $t_dir = $t_filter['dir'];
 
-$t_checkboxes_exist = false;
-
 $t_icon_path = config_get( 'icon_path' );
 $t_update_bug_threshold = config_get( 'update_bug_threshold' );
 $t_bug_resolved_status_threshold = config_get( 'bug_resolved_status_threshold' );
```
