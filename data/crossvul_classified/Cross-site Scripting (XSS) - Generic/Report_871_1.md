# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 871_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `871_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php

//require_once("guiconfig.inc"); DO NOT REQUIRE THIS!

// DO NOT REQUIRE guiconfig.inc HERE! though it contains the function display_top_tabs needed below.
// however if included it will hang filter rule generation, and might cause pf to not load any rules.
// This happens when /usr/local/pkg/*.inc files are dynamically loaded during package generation from filter.inc with function discover_pkg_rules(x).

namespace pfsense_pkg\acme;

global $acme_tab_array;

$acme_tab_array['acme'] = array();
$acme_tab_array['acme']['settings'] = Array('name' => "General settings", 'url' => "acme_generalsettings.php");
$acme_tab_array['acme']['certificates'] = Array('name' => "Certificates", 'url' => "acme_certificates.php");
$acme_tab_array['acme']['accountkeys'] = Array('name' => "Account keys", 'url' => "acme_accountkeys.php");

function display_top_tabs_active($top_tabs, $activetab) {
	$tab_array = array();
	foreach($top_tabs as $key => $tab_item){
		$tab_array[] = array($tab_item['name'], $key == $activetab, $tab_item['url']);
	}
	display_top_tabs($tab_array);
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,9 +11,9 @@
 global $acme_tab_array;
 
 $acme_tab_array['acme'] = array();
-$acme_tab_array['acme']['settings'] = Array('name' => "General settings", 'url' => "acme_generalsettings.php");
-$acme_tab_array['acme']['certificates'] = Array('name' => "Certificates", 'url' => "acme_certificates.php");
-$acme_tab_array['acme']['accountkeys'] = Array('name' => "Account keys", 'url' => "acme_accountkeys.php");
+$acme_tab_array['acme']['settings'] = Array('name' => "General settings", 'url' => "/acme/acme_generalsettings.php");
+$acme_tab_array['acme']['certificates'] = Array('name' => "Certificates", 'url' => "/acme/acme_certificates.php");
+$acme_tab_array['acme']['accountkeys'] = Array('name' => "Account keys", 'url' => "/acme/acme_accountkeys.php");
 
 function display_top_tabs_active($top_tabs, $activetab) {
 	$tab_array = array();
```
