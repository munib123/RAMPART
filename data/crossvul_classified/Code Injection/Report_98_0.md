# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 98_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `98_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
	/*
		Class: BigTreeStorage
			Facilitates the storage, deletion, and replacement of files (whether local or cloud stored).
	*/

	class BigTreeStorage {

		var $AutoJPEG = false;
		var $DisabledFileError = false;
		var $DisabledExtensionRegEx = '/\\.(exe|com|bat|php|rb|py|cgi|pl|sh|asp|aspx|phtml|pht)/i';
		var $Service = "";
		var $Cloud = false;
		var $Settings;

		/*
			Constructor:
				Retrieves the current desired service and image processing availability.
		*/

		function __construct() {
			global $cms;
			
			// Get by reference because we modify it.
			$this->Settings = &$cms->autoSaveSetting("bigtree-internal-storage");
			
			if (!empty($this->Settings->Service)) {
				if ($this->Settings->Service == "s3" || $this->Settings->Service == "amazon") {
					$this->Cloud = new BigTreeCloudStorage("amazon");
				} elseif ($this->Settings->Service == "rackspace") {
					$this->Cloud = new BigTreeCloudStorage("rackspace");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
 
 		var $AutoJPEG = false;
 		var $DisabledFileError = false;
-		var $DisabledExtensionRegEx = '/\\.(exe|com|bat|php|rb|py|cgi|pl|sh|asp|aspx|phtml|pht)/i';
+		var $DisabledExtensionRegEx = '/\\.(exe|com|bat|php|rb|py|cgi|pl|sh|asp|aspx|phtml|pht|htaccess)/i';
 		var $Service = "";
 		var $Cloud = false;
 		var $Settings;
```
