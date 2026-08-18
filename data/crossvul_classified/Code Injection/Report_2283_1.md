# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in xml
**Pair ID:** 2283_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2283_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```xml
Lines 1-26 of the vulnerable file.

<module>
	<rawname>fw_ari</rawname>
	<modtype>framework</modtype>
	<repo>standard</repo>
	<name>FreePBX ARI Framework</name>
	<version>2.11.1.4</version>
	<publisher>Schmooze Com Inc</publisher>
	<license>GPLv3+</license>
	<licenselink>http://www.gnu.org/licenses/gpl-3.0.txt</licenselink>
	<changelog>
		*2.11.1.4* Force removal of User Panel Tab
		*2.11.1.3* Delete user panel tab because it comes from this module now
		*2.11.1.2* Resolve issue of user panel tab removement
		*2.11.1.1* Tweaks
		*2.11.1.0* Allow uninstall and fix for 12 if needed or wanted
		*2.11.0.7* Include license file
		*2.11.0.6* Class conflicts with User Manager and BMO
		*2.11.0.5* #7107 ignore semicoloned lines
		*2.11.0.4* Add back in .htaccess file
		*2.11.0.3* #6165
		*2.11.0.2* Packaging of ver 2.11.0.2
		*2.11.0.0* Packaging of ver 2.11.0.0
		*2.11.0.0* bump version
		*2.10.0.5* #5885
		*2.10.0.4* re #5743 -
		*2.10.0.3* #5729 Possible Authenticated user RCE Security Vulnerability
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,11 +3,12 @@
 	<modtype>framework</modtype>
 	<repo>standard</repo>
 	<name>FreePBX ARI Framework</name>
-	<version>2.11.1.4</version>
+	<version>2.11.1.5</version>
 	<publisher>Schmooze Com Inc</publisher>
 	<license>GPLv3+</license>
 	<licenselink>http://www.gnu.org/licenses/gpl-3.0.txt</licenselink>
 	<changelog>
+		*2.11.1.5* FREEPBX-8070 SECURITY ISSUE Exec shell on a host using bug in Asterisk Recording Interface index.php
 		*2.11.1.4* Force removal of User Panel Tab
 		*2.11.1.3* Delete user panel tab because it comes from this module now
 		*2.11.1.2* Resolve issue of user panel tab removement
```
