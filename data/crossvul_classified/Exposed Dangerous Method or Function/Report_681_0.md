# CrossVul Fix Pair: Exposed Dangerous Method or Function in php
**Pair ID:** 681_0
**Vulnerability Class:** Exposed Dangerous Method or Function
**CWE:** CWE-749
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `681_0`)

## Vulnerability Information & PoC

## Description
Exposed Dangerous Method or Function - This weakness can lead to a wide variety of resultant weaknesses, depending on the behavior of the exposed method.

## Vulnerable Code
```php
Lines 3111-3151 of the vulnerable file.

						$this->AttributeTag->save($at);
					}
				}
				if (!empty($attribute['Sighting'])) {
					foreach ($attribute['Sighting'] as $k => $sighting) {
						$this->Sighting->captureSighting($sighting, $this->id, $eventId, $user);
					}
				}
			}
		return $attribute;
	}

	public function editAttribute($attribute, $eventId, $user, $objectId, $log = false) {
		$attribute['event_id'] = $eventId;
		$attribute['object_id'] = $objectId;
		if (isset($attribute['encrypt'])) {
			$result = $this->handleMaliciousBase64($eventId, $attribute['value'], $attribute['data'], array('md5'));
			$attribute['data'] = $result['data'];
			$attribute['value'] = $attribute['value'] . '|' . $result['md5'];
		}
		if (isset($attribute['uuid'])) {
			$existingAttribute = $this->find('first', array(
				'conditions' => array('Attribute.uuid' => $attribute['uuid']),
				'recursive' => -1
			));
			$this->Log = ClassRegistry::init('Log');
			if (count($existingAttribute)) {
				if ($existingAttribute['Attribute']['event_id'] != $eventId || $existingAttribute['Attribute']['object_id'] != $objectId) {
					$this->Log->create();
					$result = $this->Log->save(array(
							'org' => $user['Organisation']['name'],
							'model' => 'Attribute',
							'model_id' => 0,
							'email' => $user['email'],
							'action' => 'edit',
							'user_id' => $user['id'],
							'title' => 'Duplicate UUID found in attribute',
							'change' => 'An attribute was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $attribute['uuid'] . '. This can also be due to the same attribute (or an attribute with the same UUID) existing in a different event / object)',
					));
					return true;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3128,6 +3128,7 @@
 			$attribute['data'] = $result['data'];
 			$attribute['value'] = $attribute['value'] . '|' . $result['md5'];
 		}
+		unset($attribute['id']);
 		if (isset($attribute['uuid'])) {
 			$existingAttribute = $this->find('first', array(
 				'conditions' => array('Attribute.uuid' => $attribute['uuid']),
```
