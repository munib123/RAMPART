# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2530_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2530_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1781-1822 of the vulnerable file.

		display_install_messages( T_('You must pass db_config params or create a <code>/conf/_basic_config.php</code> file before calling the installer.') );

		$basic_config_file_result_messages = ob_get_clean();
		return false;
	}

	// Revert config admin email to original value:
	$admin_email = $default_admin_email;

	return true;
}


/**
 * Format an install param like DB config and base url
 *
 * @return string
 */
function format_install_param( $value )
{
	$value = str_replace( array( "'",  "\$" ), array( "\'", "\\$" ), $value );
	return preg_replace( "#([\\\\]*)(\\\\\\\')#", "\\\\\\\\\\\\\\\\\'", $value );
}


/**
 * Update file /conf/_basic_config.php
 *
 * @param string Current action, updated by reference
 * @param array Params
 * @return boolean TRUE on success
 */
function update_basic_config_file( $params = array() )
{
	global $DB, $db_config, $evo_charset, $conf_path, $default_locale;

	// These global params should be rewritten by this function on success result
	global $baseurl, $admin_email, $config_is_done, $action;

	$params = array_merge( array(
			'create_db'      => 0,
			'db_user'        => '',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1798,8 +1798,19 @@
  */
 function format_install_param( $value )
 {
-	$value = str_replace( array( "'",  "\$" ), array( "\'", "\\$" ), $value );
-	return preg_replace( "#([\\\\]*)(\\\\\\\')#", "\\\\\\\\\\\\\\\\\'", $value );
+	// We need backslashes only for single quote(') and backslash(\):
+	$value = addcslashes( $value, "'\\" );
+	/*
+		The below code excludes even number of slashes, because we need always odd
+		number of slashes before single quote(') to avoid a broken string value.
+		Examples for source and result:
+		  \'     => \'         (1 slash is not converted because it is used only for single quote backslashing)
+		  \\'    => \\\'       (2 slashes are converted to 3, because only first one slash must be backslashed)
+		  \\\'   => \\\\\'     (3 slashes are converted to 5, first two slashes must be backslashed)
+		  \\\\'  => \\\\\\\'   (4 slashes are converted to 7, first three slashes must be backslashed)
+		  \\\\\' => \\\\\\\\\' (5 slashes are converted to 9, first four slashes must be backslashed)
+	*/
+	return preg_replace( '#(\\\\*)(\\\')#', '$1$1$2', $value );
 }
 
 
```
