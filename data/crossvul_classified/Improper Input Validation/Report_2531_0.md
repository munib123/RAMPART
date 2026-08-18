# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2531_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2531_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1775-1815 of the vulnerable file.

	}
	elseif( ! file_exists( $conf_path.'_basic_config.php' ) )
	{
		global $basic_config_file_result_messages;

		ob_start();
		display_install_messages( T_('You must pass db_config params or create a <code>/conf/_basic_config.php</code> file before calling the installer.') );

		$basic_config_file_result_messages = ob_get_clean();
		return false;
	}

	// Revert config admin email to original value:
	$admin_email = $default_admin_email;

	return true;
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
			'db_password'    => '',
			'db_name'        => '',
			'db_host'        => '',
			'db_tableprefix' => '',
			'baseurl'        => '',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1792,6 +1792,18 @@
 
 
 /**
+ * Format an install param like DB config and base url
+ *
+ * @return string
+ */
+function format_install_param( $value )
+{
+	$value = str_replace( array( "'",  "\$" ), array( "\'", "\\$" ), $value );
+	return preg_replace( "#([\\\\]*)(\\\\\\\')#", "\\\\\\\\\\\\\\\\\'", $value );
+}
+
+
+/**
  * Update file /conf/_basic_config.php
  *
  * @param string Current action, updated by reference
@@ -1891,13 +1903,13 @@
 			),
 			array(
 				"\$db_config = array(\n"
-					."\t'user'     => '".str_replace( array( "'", "\$" ), array( "\'", "\\$" ), $params['db_user'] )."',\$1"
-					."\t'password' => '".str_replace( array( "'", "\$" ), array( "\'", "\\$" ), $params['db_password'] )."',\$2"
-					."\t'name'     => '".str_replace( array( "'", "\$" ), array( "\'", "\\$" ), $params['db_name'] )."',\$3"
-					."\t'host'     => '".str_replace( array( "'", "\$" ), array( "\'", "\\$" ), $params['db_host'] )."',\$4",
-				"tableprefix = '".str_replace( "'", "\'", $params['db_tableprefix'] )."';",
-				"baseurl = '".str_replace( "'", "\'", $params['baseurl'] )."';",
-				"admin_email = '".str_replace( "'", "\'", $params['admin_email'] )."';",
+					."\t'user'     => '".format_install_param( $params['db_user'] )."',\$1"
+					."\t'password' => '".format_install_param( $params['db_password'] )."',\$2"
+					."\t'name'     => '".format_install_param( $params['db_name'] )."',\$3"
+					."\t'host'     => '".format_install_param( $params['db_host'] )."',\$4",
+				"tableprefix = '".format_install_param( $params['db_tableprefix'] )."';",
+				"baseurl = '".format_install_param( $params['baseurl'] )."';",
+				"admin_email = '".format_install_param( $params['admin_email'] )."';",
 				'config_is_done = 1;',
 			), $conf );
 
```
