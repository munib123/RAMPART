# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 5784_8
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5784_8`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

{
	/** @var  string  Product name. */
	public $PRODUCT = 'Joomla!';

	/** @var  string  Release version. */
	public $RELEASE = '2.5';

	/** @var  string  Maintenance version. */
	public $DEV_LEVEL = '14';

	/** @var  string  Development STATUS. */
	public $DEV_STATUS = 'Stable';

	/** @var  string  Build number. */
	public $BUILD = '';

	/** @var  string  Code name. */
	public $CODENAME = 'Ember';

	/** @var  string  Release date. */
	public $RELDATE = '24-July-2013';

	/** @var  string  Release time. */
	public $RELTIME = '14:00';

	/** @var  string  Release timezone. */
	public $RELTZ = 'GMT';

	/** @var  string  Copyright Notice. */
	public $COPYRIGHT = 'Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.';

	/** @var  string  Link text. */
	public $URL = '<a href="http://www.joomla.org">Joomla!</a> is Free Software released under the GNU General Public License.';

	/**
	 * Compares two a "PHP standardized" version number against the current Joomla version.
	 *
	 * @param   string  $minimum  The minimum version of the Joomla which is compatible.
	 *
	 * @return  bool    True if the version is compatible.
	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
 	public $CODENAME = 'Ember';
 
 	/** @var  string  Release date. */
-	public $RELDATE = '24-July-2013';
+	public $RELDATE = '01-August-2013';
 
 	/** @var  string  Release time. */
 	public $RELTIME = '14:00';
```
