# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3599_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3599_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 43-84 of the vulnerable file.

require_api( 'authentication_api.php' );
require_api( 'category_api.php' );
require_api( 'config_api.php' );
require_api( 'constant_inc.php' );
require_api( 'database_api.php' );
require_api( 'form_api.php' );
require_api( 'gpc_api.php' );
require_api( 'helper_api.php' );
require_api( 'html_api.php' );
require_api( 'lang_api.php' );
require_api( 'print_api.php' );
require_api( 'string_api.php' );

form_security_validate( 'manage_proj_cat_delete' );

auth_reauthenticate();

$f_category_id = gpc_get_int( 'id' );
$f_project_id = gpc_get_int( 'project_id' );

access_ensure_project_level( config_get( 'manage_project_threshold' ), $f_project_id );

$t_row = category_get_row( $f_category_id );
$t_name = category_full_name( $f_category_id );
$t_project_id = $t_row['project_id'];

# Get a bug count
$t_bug_table = db_get_table( 'bug' );
$t_query = "SELECT COUNT(id) FROM $t_bug_table WHERE category_id=" . db_param();
$t_bug_count = db_result( db_query_bound( $t_query, array( $f_category_id ) ) );

# Confirm with the user
helper_ensure_confirmed( sprintf( lang_get( 'category_delete_sure_msg' ), string_display_line( $t_name ), $t_bug_count ),
	lang_get( 'delete_category_button' ) );

category_remove( $f_category_id );

form_security_purge( 'manage_proj_cat_delete' );

if ( $f_project_id == ALL_PROJECTS ) {
	$t_redirect_url = 'manage_proj_page.php';
} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,11 +60,11 @@
 $f_category_id = gpc_get_int( 'id' );
 $f_project_id = gpc_get_int( 'project_id' );
 
-access_ensure_project_level( config_get( 'manage_project_threshold' ), $f_project_id );
-
 $t_row = category_get_row( $f_category_id );
 $t_name = category_full_name( $f_category_id );
 $t_project_id = $t_row['project_id'];
+
+access_ensure_project_level( config_get( 'manage_project_threshold' ), $t_project_id );
 
 # Get a bug count
 $t_bug_table = db_get_table( 'bug' );
```
