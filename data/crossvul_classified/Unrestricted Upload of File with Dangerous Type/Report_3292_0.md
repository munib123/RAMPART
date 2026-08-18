# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 3292_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3292_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

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
		var $DisabledExtensionRegEx = '/\\.(exe|com|bat|php|rb|py|cgi|pl|sh|asp|aspx)$/i';
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
-		var $DisabledExtensionRegEx = '/\\.(exe|com|bat|php|rb|py|cgi|pl|sh|asp|aspx)$/i';
+		var $DisabledExtensionRegEx = '/\\.(exe|com|bat|php|rb|py|cgi|pl|sh|asp|aspx)/i';
 		var $Service = "";
 		var $Cloud = false;
 		var $Settings;
```
