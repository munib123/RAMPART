# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 2636_0
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2636_0`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 606-646 of the vulnerable file.

	}


	/**
	 * Calculate the NameID value that should be used.
	 *
	 * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
	 * @param SimpleSAML_Configuration $dstMetadata  The metadata of the SP.
	 * @param array &$state  The authentication state of the user.
	 * @return string  The NameID value.
	 */
	private static function generateNameIdValue(SimpleSAML_Configuration $idpMetadata,
		SimpleSAML_Configuration $spMetadata, array &$state) {

		$attribute = $spMetadata->getString('simplesaml.nameidattribute', NULL);
		if ($attribute === NULL) {
			$attribute = $idpMetadata->getString('simplesaml.nameidattribute', NULL);
			if ($attribute === NULL) {
				if (!isset($state['UserID'])) {
					SimpleSAML_Logger::error('Unable to generate NameID. Check the userid.attribute option.');
				}
				$attributeValue = $state['UserID'];
				$idpEntityId = $idpMetadata->getString('entityid');
				$spEntityId = $spMetadata->getString('entityid');

				$secretSalt = SimpleSAML\Utils\Config::getSecretSalt();

				$uidData = 'uidhashbase' . $secretSalt;
				$uidData .= strlen($idpEntityId) . ':' . $idpEntityId;
				$uidData .= strlen($spEntityId) . ':' . $spEntityId;
				$uidData .= strlen($attributeValue) . ':' . $attributeValue;
				$uidData .= $secretSalt;

				return hash('sha1', $uidData);
			}
		}

		$attributes = $state['Attributes'];
		if (!array_key_exists($attribute, $attributes)) {
			SimpleSAML_Logger::error('Unable to add NameID: Missing ' . var_export($attribute, TRUE) .
				' in the attributes of the user.');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -623,6 +623,7 @@
 			if ($attribute === NULL) {
 				if (!isset($state['UserID'])) {
 					SimpleSAML_Logger::error('Unable to generate NameID. Check the userid.attribute option.');
+					return NULL;
 				}
 				$attributeValue = $state['UserID'];
 				$idpEntityId = $idpMetadata->getString('entityid');
```
