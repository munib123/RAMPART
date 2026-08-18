# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2341_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2341_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 165-205 of the vulnerable file.

	$t_filter_project_value = gpc_get_int( 'filter_project_id', ALL_PROJECTS );
	$t_filter_config_value  = gpc_get_string( 'filter_config_id', META_FILTER_NONE );
}

# Manage filter's persistency through cookie
$t_cookie_name = config_get( 'manage_config_cookie' );
if( $t_filter_save ) {
	# Save user's filter to the cookie
	$t_cookie_string = implode(
		':',
		array(
			$t_filter_user_value,
			$t_filter_project_value,
			$t_filter_config_value,
		)
	);
	gpc_set_cookie( $t_cookie_name, $t_cookie_string, true );
} else {
	# Retrieve the filter from the cookie if it exists
	$t_cookie_string = gpc_get_cookie( $t_cookie_name, null );
	if( null !== $t_cookie_string ) {
		$t_cookie_contents = explode( ':', $t_cookie_string );

		$t_filter_user_value    = $t_cookie_contents[0];
		$t_filter_project_value = $t_cookie_contents[1];
		$t_filter_config_value  = $t_cookie_contents[2];

		if( $t_filter_project_value != META_FILTER_NONE && !project_exists( $t_filter_project_value ) ) {
			$t_filter_project_value = ALL_PROJECTS;
		}
	}
}

# Get config edit values
$t_edit_user_id         = gpc_get_int( 'user_id', $t_filter_user_value == META_FILTER_NONE ? ALL_USERS : $t_filter_user_value );
$t_edit_project_id      = gpc_get_int( 'project_id', $t_filter_project_value == META_FILTER_NONE ? ALL_PROJECTS : $t_filter_project_value );
$t_edit_option          = gpc_get_string( 'config_option', $t_filter_config_value == META_FILTER_NONE ? '' : $t_filter_config_value );
$t_edit_type            = gpc_get_string( 'type', CONFIG_TYPE_DEFAULT );
$t_edit_value           = gpc_get_string( 'value', '' );

# Apply filters
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,6 +182,7 @@
 } else {
 	# Retrieve the filter from the cookie if it exists
 	$t_cookie_string = gpc_get_cookie( $t_cookie_name, null );
+
 	if( null !== $t_cookie_string ) {
 		$t_cookie_contents = explode( ':', $t_cookie_string );
 
@@ -192,6 +193,16 @@
 		if( $t_filter_project_value != META_FILTER_NONE && !project_exists( $t_filter_project_value ) ) {
 			$t_filter_project_value = ALL_PROJECTS;
 		}
+	}
+}
+
+if( !is_blank( $t_filter_config_value ) && (int)$t_filter_config_value !== META_FILTER_NONE ) {
+	// check that config value exists
+	if( @config_get_global( $t_filter_config_value ) === null ) {
+		$t_cookie_path = config_get( 'cookie_path' );
+		gpc_clear_cookie( $t_cookie_name, $t_cookie_path );
+
+		trigger_error( ERROR_GENERIC, ERROR );
 	}
 }
 
```
