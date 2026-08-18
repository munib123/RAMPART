# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3818_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3818_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 34-74 of the vulnerable file.

	 * @return {Array} Array of suggestions for the specified word.
	 */
	function &getSuggestions($lang, $word) {
		$sug = array();
		$osug = array();
		$matches = $this->_getMatches($lang, $word);

		if (count($matches) > 0)
			$sug = explode("\t", utf8_encode($this->_unhtmlentities($matches[0][4])));

		// Remove empty
		foreach ($sug as $item) {
			if ($item)
				$osug[] = $item;
		}

		return $osug;
	}

	function &_getMatches($lang, $str) {
		$server = "www.google.com";
		$port = 443;
		$path = "/tbproxy/spell?lang=" . $lang . "&hl=en";
		$host = "www.google.com";
		$url = "https://" . $server;

		// Setup XML request
		$xml = '<?xml version="1.0" encoding="utf-8" ?><spellrequest textalreadyclipped="0" ignoredups="0" ignoredigits="1" ignoreallcaps="1"><text>' . $str . '</text></spellrequest>';

		$header  = "POST ".$path." HTTP/1.0 \r\n";
		$header .= "MIME-Version: 1.0 \r\n";
		$header .= "Content-type: application/PTI26 \r\n";
		$header .= "Content-length: ".strlen($xml)." \r\n";
		$header .= "Content-transfer-encoding: text \r\n";
		$header .= "Request-number: 1 \r\n";
		$header .= "Document-type: Request \r\n";
		$header .= "Interface-Version: Test 1.4 \r\n";
		$header .= "Connection: close \r\n\r\n";
		$header .= $xml;

		// Use curl if it exists
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,6 +51,8 @@
 	}
 
 	function &_getMatches($lang, $str) {
+		$lang = preg_replace('/[^a-z\-]/i', '', $lang); // Sanitize, remove everything but a-z or -
+		$str = preg_replace('/[\x00-\x1F\x7F]/', '', $str); // Sanitize, remove all control characters
 		$server = "www.google.com";
 		$port = 443;
 		$path = "/tbproxy/spell?lang=" . $lang . "&hl=en";
```
