# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3202_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3202_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 71-111 of the vulnerable file.

		$visitor->Store();

		$_SESSION['last_route'] = isset($_GET['route']) ? $_GET['route'] : NULL;
	}

	public function get_dbc()
	{
		return $this->db->get_connection();
	}

	public function set_controller($controller, $action)
	{
		include CLASS_DIR . 'module.php';

		$module = new Module($controller);

		define ('MODULE_NAME', $module->get_name());

		$class_file = APP_DIR . 'controller/' . MODULE_NAME . '.php';
		$class_name = ucfirst(MODULE_NAME) . '_Controller';
		$class_method = ucfirst($action) . '_Action';

		// tworzy obiekt kontrolera:

		if (file_exists($class_file))
		{
			include $class_file;

			if (class_exists($class_name))
			{
				$this->controller_object = new $class_name($this);

				$this->set_acl($this);
			}
			else
			{
				die ('Class: <h3>'.$class_name.'</h3> not found.');
			}
		}
		else
		{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,7 @@
 
 		$class_file = APP_DIR . 'controller/' . MODULE_NAME . '.php';
 		$class_name = ucfirst(MODULE_NAME) . '_Controller';
-		$class_method = ucfirst($action) . '_Action';
+		$class_method = ucfirst(strip_tags($action)) . '_Action';
 
 		// tworzy obiekt kontrolera:
 
```
