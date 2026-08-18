# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3610_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3610_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 148-188 of the vulnerable file.

			$this->tpl->assign('report', true);

			// camelcase the string
			$messageName = strip_tags(SpoonFilter::toCamelCase($this->getParameter('report'), '-'));

			// if we have data to use it will be passed as the var parameter
			if(!empty($var)) $this->tpl->assign('reportMessage', vsprintf(BL::msg($messageName), $var));
			else $this->tpl->assign('reportMessage', BL::msg($messageName));

			// highlight an element with the given id if needed
			if($this->getParameter('highlight'))
			{
				$this->tpl->assign('highlight', strip_tags($this->getParameter('highlight')));
			}
		}

		// is there an error to show?
		if($this->getParameter('error') !== null)
		{
			// camelcase the string
			$errorName = SpoonFilter::toCamelCase($this->getParameter('error'), '-');

			// if we have data to use it will be passed as the var parameter
			if(!empty($var)) $this->tpl->assign('errorMessage', vsprintf(BL::err($errorName), $var));
			else $this->tpl->assign('errorMessage', BL::err($errorName));
		}
	}

	/**
	 * Get the action
	 *
	 * @return string
	 */
	public function getAction()
	{
		return $this->action;
	}

	/**
	 * Get the module
	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,7 +165,7 @@
 		if($this->getParameter('error') !== null)
 		{
 			// camelcase the string
-			$errorName = SpoonFilter::toCamelCase($this->getParameter('error'), '-');
+			$errorName = strip_tags(SpoonFilter::toCamelCase($this->getParameter('error'), '-'));
 
 			// if we have data to use it will be passed as the var parameter
 			if(!empty($var)) $this->tpl->assign('errorMessage', vsprintf(BL::err($errorName), $var));
```
