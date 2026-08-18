# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 2793_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2793_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 116-156 of the vulnerable file.

				}
				if ($k) {
					$v = $m[3][$i];
					$r[$k] = $v;
				}
				unset($m[0][$i], $m[1][$i], $m[2][$i], $m[3][$i], $k, $v, $i);
			}
		}
		return $r;
	}

	// to enable stateless authentication
	public function getUser(CakeRequest $request)
	{
		if (empty(self::$user)) {
			if (self::$client) {
				self::$user = self::$client;
				// If $sync is true, allow the creation of the user from the certificate
				$sync = Configure::read('CertAuth.syncUser');
				if ($sync) {
					self::getRestUser();
				}

				// find and fill user with model
				$userModelKey = empty(Configure::read('CertAuth.userModelKey')) ? 'email' : Configure::read('CertAuth.userModelKey');
				$userDefaults = Configure::read('CertAuth.userDefaults');
				$this->User = ClassRegistry::init('User');
				$existingUser = $this->User->find('first', array(
					'conditions' => array($userModelKey => self::$user[$userModelKey]),
					'recursive' => false
				));
				if ($existingUser) {
					if ($sync) {
						if (!isset(self::$user['org_id']) && isset(self::$user['org'])) {
							self::$user['org_id'] = $this->User->Organisation->createOrgFromName(self::$user['org'], $existingUser['User']['id'], true);
							// reset user defaults in case it's a different org_id
							if (self::$user['org_id'] && $existingUser['User']['org_id'] != self::$user['org_id']) {
								if ($userDefaults && is_array($userDefaults)) {
									self::$user = array_merge($userDefaults + self::$user);
								}
							}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,17 +133,19 @@
 				// If $sync is true, allow the creation of the user from the certificate
 				$sync = Configure::read('CertAuth.syncUser');
 				if ($sync) {
-					self::getRestUser();
+					if (!self::getRestUser()) return false;
 				}
 
 				// find and fill user with model
 				$userModelKey = empty(Configure::read('CertAuth.userModelKey')) ? 'email' : Configure::read('CertAuth.userModelKey');
 				$userDefaults = Configure::read('CertAuth.userDefaults');
 				$this->User = ClassRegistry::init('User');
-				$existingUser = $this->User->find('first', array(
-					'conditions' => array($userModelKey => self::$user[$userModelKey]),
-					'recursive' => false
-				));
+				if (!empty(self::$user[$userModelKey])) {
+					$existingUser = $this->User->find('first', array(
+						'conditions' => array($userModelKey => self::$user[$userModelKey]),
+						'recursive' => false
+					));
+				}
 				if ($existingUser) {
 					if ($sync) {
 						if (!isset(self::$user['org_id']) && isset(self::$user['org'])) {
```
