# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3608_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3608_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 177-199 of the vulnerable file.

	 */
	private function setLanguage($value)
	{
		// set property
		$this->language = (string) $value;

		// define constant
		define('FRONTEND_LANGUAGE', $this->language);

		// set the locale (we need this for the labels)
		FrontendLanguage::setLocale($this->language);
	}

	/**
	 * Set module
	 *
	 * @param string $value The module.
	 */
	private function setModule($value)
	{
		$this->module = (string) $value;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,6 +194,17 @@
 	 */
 	private function setModule($value)
 	{
+		$modules = (array) FrontendModel::getModules();
+		
+		if(!in_array((string) $value, $modules))
+		{
+			// when debug is on throw an exception
+			if(SPOON_DEBUG) throw new FrontendException('Invalid file.');
+
+			// when debug is of show a descent message
+			else exit(SPOON_DEBUG_MESSAGE);
+		}
+		
 		$this->module = (string) $value;
 	}
 }
```
