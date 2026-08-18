# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3778_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3778_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 197-223 of the vulnerable file.

			if(strpos($item['full_url'], '?') !== false) $glue = '&';
			else $glue = '?';

			// add utm to url
			$item['full_url'] .= $glue . http_build_query($utm, '', '&');

			// format description
			$item['text'] = !empty($item['text']) ? (mb_strlen($item['text']) > $this->length ? mb_substr(strip_tags($item['text']), 0, $this->length, SPOON_CHARSET) . '…' : $item['text']) : '';
		}

		// output
		$this->output(self::OK, $this->items);
	}

	/**
	 * Validate the form
	 */
	private function validateForm()
	{
		// set values
		$this->term = SpoonFilter::getPostValue('term', null, '');
		$this->length = (int) SpoonFilter::getPostValue('length', null, 50);

		// validate
		if($this->term == '') $this->output(self::BAD_REQUEST, null, 'term-parameter is missing.');
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,7 +214,8 @@
 	private function validateForm()
 	{
 		// set values
-		$this->term = SpoonFilter::getPostValue('term', null, '');
+		$searchTerm = SpoonFilter::getPostValue('term', null, '');
+		$this->term = (SPOON_CHARSET == 'utf-8') ? SpoonFilter::htmlspecialchars($searchTerm) : SpoonFilter::htmlentities($searchTerm);
 		$this->length = (int) SpoonFilter::getPostValue('length', null, 50);
 
 		// validate
```
