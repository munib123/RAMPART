# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1480_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1480_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 78-118 of the vulnerable file.


	foreach ($input as $varname)
	{
		if (isset($not_unset[$varname]))
		{
			// Hacking attempt. No point in continuing.
			if (isset($_COOKIE[$varname]))
			{
				echo "Clear your cookies. ";
			}
			echo "Malicious variable name detected. Contact the administrator and ask them to disable register_globals.";
			exit;
		}

		unset($GLOBALS[$varname]);
	}

	unset($input);
}

// Register globals and magic quotes have been dropped in PHP 5.4
if (version_compare(PHP_VERSION, '5.4.0-dev', '>='))
{
	/**
	* @ignore
	*/
	define('STRIP', false);
}
else
{
	@set_magic_quotes_runtime(0);

	// Be paranoid with passed vars
	if (@ini_get('register_globals') == '1' || strtolower(@ini_get('register_globals')) == 'on' || !function_exists('ini_get'))
	{
		deregister_globals();
	}

	define('STRIP', (get_magic_quotes_gpc()) ? true : false);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,54 @@
 	unset($input);
 }
 
+/**
+ * Check if requested page uses a trailing path
+ *
+ * @param string $phpEx PHP extension
+ *
+ * @return bool True if trailing path is used, false if not
+ */
+function phpbb_has_trailing_path($phpEx)
+{
+	// Check if path_info is being used
+	if (!empty($_SERVER['PATH_INFO']) || !empty($_SERVER['ORIG_PATH_INFO']))
+	{
+		return true;
+	}
+
+	// Match any trailing path appended to a php script in the REQUEST_URI.
+	// It is assumed that only actual PHP scripts use names like foo.php. Due
+	// to this, any phpBB board inside a directory that has the php extension
+	// appended to its name will stop working, i.e. if the board is at
+	// example.com/phpBB/test.php/ or example.com/test.php/
+	if (preg_match('#^[^?]+\.' . preg_quote($phpEx, '#') . '/#', $_SERVER['REQUEST_URI']))
+	{
+		return true;
+	}
+
+	return false;
+}
+
+// Check if trailing path is used
+if (phpbb_has_trailing_path($phpEx))
+{
+	if (substr(strtolower(@php_sapi_name()), 0, 3) === 'cgi')
+	{
+		$prefix = 'Status:';
+	}
+	else if (!empty($_SERVER['SERVER_PROTOCOL']))
+	{
+		$prefix = $_SERVER['SERVER_PROTOCOL'];
+	}
+	else
+	{
+		$prefix = 'HTTP/1.0';
+	}
+	header("$prefix 404 Not Found", true, 404);
+	echo 'Trailing paths and PATH_INFO is not supported by phpBB 3.0';
+	exit;
+}
+
 // Register globals and magic quotes have been dropped in PHP 5.4
 if (version_compare(PHP_VERSION, '5.4.0-dev', '>='))
 {
```
