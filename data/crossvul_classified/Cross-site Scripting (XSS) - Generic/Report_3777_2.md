# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3777_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3777_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 348-373 of the vulnerable file.

			else $URL = $this->pagination['url'] . '&amp;page=' . ($this->pagination['requested_page'] + 1);

			// set
			$pagination['show_next'] = true;
			$pagination['next_url'] = $URL;
		}

		// multiple pages
		$pagination['multiple_pages'] = ($pagination['num_pages'] == 1) ? false : true;

		// assign pagination
		$this->tpl->assign('pagination', $pagination);
	}

	/**
	 * Validate the form
	 */
	private function validateForm()
	{
		// set search term
		$this->term = SpoonFilter::getPostValue('term', null, '');

		// validate
		if($this->term == '') $this->output(self::BAD_REQUEST, null, 'term-parameter is missing.');
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -365,7 +365,8 @@
 	private function validateForm()
 	{
 		// set search term
-		$this->term = SpoonFilter::getPostValue('term', null, '');
+		$searchTerm = SpoonFilter::getPostValue('term', null, '');
+		$this->term = (SPOON_CHARSET == 'utf-8') ? SpoonFilter::htmlspecialchars($searchTerm) : SpoonFilter::htmlentities($searchTerm);
 
 		// validate
 		if($this->term == '') $this->output(self::BAD_REQUEST, null, 'term-parameter is missing.');
```
