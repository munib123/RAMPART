# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3753_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3753_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 170-210 of the vulnerable file.

	/**
	* @brief Tries to update imported VCards to adhere to rfc2426 (VERSION: 3.0) and add mandatory fields if missing.
	* @param aid Address book id.
	* @param vcard An OC_VObject of type VCARD (passed by reference).
	*/
	protected static function updateValuesFromAdd($aid, &$vcard) { // any suggestions for a better method name? ;-)
		$stringprops = array('N', 'FN', 'ORG', 'NICK', 'ADR', 'NOTE');
		$typeprops = array('ADR', 'TEL', 'EMAIL');
		$upgrade = false;
		$fn = $n = $uid = $email = $org = null;
		$version = $vcard->getAsString('VERSION');
		// Add version if needed
		if($version && $version < '3.0') {
			$upgrade = true;
			OCP\Util::writeLog('contacts','OC_Contacts_VCard::updateValuesFromAdd. Updating from version: '.$version,OCP\Util::DEBUG);
		}
		foreach($vcard->children as &$property){
			// Decode string properties and remove obsolete properties.
			if($upgrade && in_array($property->name, $stringprops)) {
				self::decodeProperty($property);
			}
			// Fix format of type parameters.
			if($upgrade && in_array($property->name, $typeprops)) {
				OCP\Util::writeLog('contacts','OC_Contacts_VCard::updateValuesFromAdd. before: '.$property->serialize(),OCP\Util::DEBUG);
				self::formatPropertyTypes($property);
				OCP\Util::writeLog('contacts','OC_Contacts_VCard::updateValuesFromAdd. after: '.$property->serialize(),OCP\Util::DEBUG);
			}
			if($property->name == 'FN'){
				$fn = $property->value;
			}
			if($property->name == 'N'){
				$n = $property->value;
			}
			if($property->name == 'UID'){
				$uid = $property->value;
			}
			if($property->name == 'ORG'){
				$org = $property->value;
			}
			if($property->name == 'EMAIL' && is_null($email)){ // only use the first email as substitute for missing N or FN.
				$email = $property->value;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,6 +188,9 @@
 			if($upgrade && in_array($property->name, $stringprops)) {
 				self::decodeProperty($property);
 			}
+			if(in_array($property->name, $stringprops)) {
+				$property->value = strip_tags($property->value);
+			}
 			// Fix format of type parameters.
 			if($upgrade && in_array($property->name, $typeprops)) {
 				OCP\Util::writeLog('contacts','OC_Contacts_VCard::updateValuesFromAdd. before: '.$property->serialize(),OCP\Util::DEBUG);
```
