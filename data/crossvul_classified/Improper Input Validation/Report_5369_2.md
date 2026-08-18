# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 5369_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5369_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

	 *
	 * @var    string
	 * @since  3.5
	 */
	const PRODUCT = 'Joomla!';

	/**
	 * Release version.
	 *
	 * @var    string
	 * @since  3.5
	 */
	const RELEASE = '3.6';

	/**
	 * Maintenance version.
	 *
	 * @var    string
	 * @since  3.5
	 */
	const DEV_LEVEL = '4-dev';

	/**
	 * Development status.
	 *
	 * @var    string
	 * @since  3.5
	 */
	const DEV_STATUS = 'Development';

	/**
	 * Build number.
	 *
	 * @var    string
	 * @since  3.5
	 */
	const BUILD = '';

	/**
	 * Code name.
	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
 	 * @var    string
 	 * @since  3.5
 	 */
-	const DEV_LEVEL = '4-dev';
+	const DEV_LEVEL = '4';
 
 	/**
 	 * Development status.
@@ -46,7 +46,7 @@
 	 * @var    string
 	 * @since  3.5
 	 */
-	const DEV_STATUS = 'Development';
+	const DEV_STATUS = 'Stable';
 
 	/**
 	 * Build number.
@@ -70,7 +70,7 @@
 	 * @var    string
 	 * @since  3.5
 	 */
-	const RELDATE = '18-October-2016';
+	const RELDATE = '21-October-2016';
 
 	/**
 	 * Release time.
@@ -78,7 +78,7 @@
 	 * @var    string
 	 * @since  3.5
 	 */
-	const RELTIME = '16:37';
+	const RELTIME = '16:33';
 
 	/**
 	 * Release timezone.
```
