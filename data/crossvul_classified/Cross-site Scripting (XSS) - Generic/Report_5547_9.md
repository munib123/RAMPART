# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5547_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5547_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 332-376 of the vulnerable file.

 * Sets a private setting for an entity.
 *
 * @param int    $entity_guid The entity GUID
 * @param string $name        The name of the setting
 * @param string $value       The value of the setting
 *
 * @return bool
 * @see get_private_setting()
 * @see get_all_private_settings()
 * @see remove_private_setting()
 * @see remove_all_private_settings()
 * @link http://docs.elgg.org/DataModel/Entities/PrivateSettings
 */
function set_private_setting($entity_guid, $name, $value) {
	global $CONFIG;

	$entity_guid = (int) $entity_guid;
	$name = sanitise_string($name);
	$value = sanitise_string($value);

	$entity = get_entity($entity_guid);
	if (!$entity instanceof ElggEntity) {
		return false;
	}

	$result = insert_data("INSERT into {$CONFIG->dbprefix}private_settings
		(entity_guid, name, value) VALUES
		($entity_guid, '$name', '$value')
		ON DUPLICATE KEY UPDATE value='$value'");

	return $result !== false;
}

/**
 * Deletes a private setting for an entity.
 *
 * @param int    $entity_guid The Entity GUID
 * @param string $name        The name of the setting
 *
 * @return bool
 * @see get_private_setting()
 * @see get_all_private_settings()
 * @see set_private_setting()
 * @see remove_all_private_settings()
 * @link http://docs.elgg.org/DataModel/Entities/PrivateSettings
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -349,11 +349,6 @@
 	$name = sanitise_string($name);
 	$value = sanitise_string($value);
 
-	$entity = get_entity($entity_guid);
-	if (!$entity instanceof ElggEntity) {
-		return false;
-	}
-
 	$result = insert_data("INSERT into {$CONFIG->dbprefix}private_settings
 		(entity_guid, name, value) VALUES
 		($entity_guid, '$name', '$value')
```
