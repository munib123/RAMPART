# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2390_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2390_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 40-83 of the vulnerable file.


require_once( 'core.php' );
require_api( 'access_api.php' );
require_api( 'authentication_api.php' );
require_api( 'config_api.php' );
require_api( 'constant_inc.php' );
require_api( 'database_api.php' );
require_api( 'gpc_api.php' );
require_api( 'helper_api.php' );
require_api( 'html_api.php' );
require_api( 'icon_api.php' );
require_api( 'lang_api.php' );
require_api( 'print_api.php' );
require_api( 'string_api.php' );
require_api( 'utility_api.php' );

auth_reauthenticate();

access_ensure_global_level( config_get( 'manage_user_threshold' ) );

$f_sort	         = gpc_get_string( 'sort', 'username' );
$f_dir	         = gpc_get_string( 'dir', 'ASC' );
$f_hide_inactive = gpc_get_bool( 'hideinactive' );
$f_show_disabled = gpc_get_bool( 'showdisabled' );
$f_save          = gpc_get_bool( 'save' );
$f_filter        = utf8_strtoupper( gpc_get_string( 'filter', config_get( 'default_manage_user_prefix' ) ) );
$f_page_number   = gpc_get_int( 'page_number', 1 );

$t_cookie_name = config_get( 'manage_users_cookie' );
$t_lock_image = '<img src="' . config_get( 'icon_path' ) . 'protected.gif" width="8" height="15" alt="' . lang_get( 'protected' ) . '" />';
$c_filter = '';

# Clean up the form variables
if( !db_field_exists( $f_sort, db_get_table( 'user' ) ) ) {
	$c_sort = 'username';
} else {
	$c_sort = addslashes( $f_sort );
}

$c_dir = ( $f_dir == 'ASC' ) ? 'ASC' : 'DESC';

# 0 = show inactive users, anything else = hide them
$c_hide_inactive = ( $f_hide_inactive == 0 ) ? 0 : 1;
$t_hide_inactive_filter = '&amp;hideinactive=' . $c_hide_inactive;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,17 +57,44 @@
 
 access_ensure_global_level( config_get( 'manage_user_threshold' ) );
 
-$f_sort	         = gpc_get_string( 'sort', 'username' );
-$f_dir	         = gpc_get_string( 'dir', 'ASC' );
-$f_hide_inactive = gpc_get_bool( 'hideinactive' );
-$f_show_disabled = gpc_get_bool( 'showdisabled' );
+$t_cookie_name = config_get( 'manage_users_cookie' );
+$t_lock_image = '<img src="' . config_get( 'icon_path' ) . 'protected.gif" width="8" height="15" border="0" alt="' . lang_get( 'protected' ) . '" />';
+$c_filter = '';
+
 $f_save          = gpc_get_bool( 'save' );
 $f_filter        = utf8_strtoupper( gpc_get_string( 'filter', config_get( 'default_manage_user_prefix' ) ) );
 $f_page_number   = gpc_get_int( 'page_number', 1 );
 
-$t_cookie_name = config_get( 'manage_users_cookie' );
-$t_lock_image = '<img src="' . config_get( 'icon_path' ) . 'protected.gif" width="8" height="15" alt="' . lang_get( 'protected' ) . '" />';
-$c_filter = '';
+if( !$f_save && !is_blank( gpc_get_cookie( $t_cookie_name, '' ) ) ) {
+	$t_manage_arr = explode( ':', gpc_get_cookie( $t_cookie_name ) );
+
+	# Hide Inactive
+	$f_hide_inactive = (bool)$t_manage_arr[0];
+
+	# Sort field
+	if ( isset( $t_manage_arr[1] ) ) {
+		$f_sort = $t_manage_arr[1];
+	} else {
+		$f_sort = 'username';
+	}
+
+	# Sort order
+	if ( isset( $t_manage_arr[2] ) ) {
+		$f_dir = $t_manage_arr[2];
+	} else {
+		$f_dir = 'DESC';
+	}
+
+	# Show Disabled
+	if ( isset( $t_manage_arr[3] ) ) {
+		$f_show_disabled = $t_manage_arr[3];
+	}
+} else {
+	$f_sort          = gpc_get_string( 'sort', 'username' );
+	$f_dir           = gpc_get_string( 'dir', 'ASC' );
+	$f_hide_inactive = gpc_get_bool( 'hideinactive' );
+	$f_show_disabled = gpc_get_bool( 'showdisabled' );
+}
 
 # Clean up the form variables
 if( !db_field_exists( $f_sort, db_get_table( 'user' ) ) ) {
@@ -90,30 +117,6 @@
 if( $f_save ) {
 	$t_manage_string = $c_hide_inactive.':'.$c_sort.':'.$c_dir.':'.$c_show_disabled;
 	gpc_set_cookie( $t_cookie_name, $t_manage_string, true );
-} else if( !is_blank( gpc_get_cookie( $t_cookie_name, '' ) ) ) {
-	$t_manage_arr = explode( ':', gpc_get_cookie( $t_cookie_name ) );
-
-	# Hide Inactive
-	$c_hide_inactive = $t_manage_arr[0];
-
-	# Sort field
-	if( isset( $t_manage_arr[1] ) ) {
-		$c_sort = $t_manage_arr[1];
-	} else {
-		$c_sort = 'username';
-	}
-
-	# Sort order
-	if( isset( $t_manage_arr[2] ) ) {
-		$c_dir  = $t_manage_arr[2];
-	} else {
-		$c_dir = 'DESC';
-	}
-
-	# Show Disabled
-	if( isset( $t_manage_arr[3] ) ) {
-		$c_show_disabled = $t_manage_arr[3];
-	}
 }
 
 html_page_top( lang_get( 'manage_users_link' ) );
```
