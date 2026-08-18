# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3609_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3609_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 131-171 of the vulnerable file.

		$this->header->addCSS('jquery_ui/fork/jquery_ui.css', 'core', false, false);
		$this->header->addCSS('screen.css', 'core');
		$this->header->addCSS('debug.css', 'core');

		// add module specific css
		if(SpoonFile::exists(BACKEND_MODULE_PATH . '/layout/css/' . $this->getModule() . '.css'))
		{
			$this->header->addCSS($this->getModule() . '.css');
		}

		// store var so we don't have to call this function twice
		$var = $this->getParameter('var', 'array');

		// is there a report to show?
		if($this->getParameter('report') !== null)
		{
			// show the report
			$this->tpl->assign('report', true);

			// camelcase the string
			$messageName = SpoonFilter::toCamelCase($this->getParameter('report'), '-');

			// if we have data to use it will be passed as the var parameter
			if(!empty($var)) $this->tpl->assign('reportMessage', vsprintf(BL::msg($messageName), $var));
			else $this->tpl->assign('reportMessage', BL::msg($messageName));

			// highlight an element with the given id if needed
			if($this->getParameter('highlight')) $this->tpl->assign('highlight', $this->getParameter('highlight'));
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,7 +148,7 @@
 			$this->tpl->assign('report', true);
 
 			// camelcase the string
-			$messageName = SpoonFilter::toCamelCase($this->getParameter('report'), '-');
+			$messageName = strip_tags(SpoonFilter::toCamelCase($this->getParameter('report'), '-'));
 
 			// if we have data to use it will be passed as the var parameter
 			if(!empty($var)) $this->tpl->assign('reportMessage', vsprintf(BL::msg($messageName), $var));
```
