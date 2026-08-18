# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3611_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3611_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php

/*
 * This file is part of Fork CMS.
 *
 * For the full copyright and license information, please view the license
 * file that was distributed with this source code.
 */

/**
 * This class implements a lot of functionality that can be extended by a specific action
 *
 * @author Tijs Verkoyen <tijs@sumocoders.be>
 */
class BackendBaseAction
{
	/**
	 * The current action
	 *
	 * @var	string
	 */
	protected $action;

	/**
	 * The parameters (urldecoded)
	 *
	 * @var	array
	 */
	protected $parameters = array();

	/**
	 * The header object
	 *
	 * @var	BackendHeader
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
  * This class implements a lot of functionality that can be extended by a specific action
  *
  * @author Tijs Verkoyen <tijs@sumocoders.be>
+ * @author Frederik Heyninck <frederik@figure8.be>
  */
 class BackendBaseAction
 {
@@ -168,21 +169,21 @@
 			$this->tpl->assign('report', true);
 
 			// camelcase the string
-			$messageName = SpoonFilter::toCamelCase($this->getParameter('report'), '-');
+			$messageName = SpoonFilter::toCamelCase(SpoonFilter::stripHTML($this->getParameter('report')), '-');
 
 			// if we have data to use it will be passed as the var parameter
 			if(!empty($var)) $this->tpl->assign('reportMessage', vsprintf(BL::msg($messageName), $var));
 			else $this->tpl->assign('reportMessage', BL::msg($messageName));
 
 			// highlight an element with the given id if needed
-			if($this->getParameter('highlight')) $this->tpl->assign('highlight', $this->getParameter('highlight'));
+			if($this->getParameter('highlight')) $this->tpl->assign('highlight', SpoonFilter::stripHTML($this->getParameter('highlight')));
 		}
 
 		// is there an error to show?
 		if($this->getParameter('error') !== null)
 		{
 			// camelcase the string
-			$errorName = SpoonFilter::toCamelCase($this->getParameter('error'), '-');
+			$errorName = SpoonFilter::toCamelCase(SpoonFilter::stripHTML($this->getParameter('error')), '-');
 
 			// if we have data to use it will be passed as the var parameter
 			if(!empty($var)) $this->tpl->assign('errorMessage', vsprintf(BL::err($errorName), $var));
```
