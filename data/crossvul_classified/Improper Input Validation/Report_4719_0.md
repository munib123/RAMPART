# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4719_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4719_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 601-641 of the vulnerable file.

		}
		$token = $data['_Token']['key'];

		if ($this->Session->check('_Token')) {
			$tokenData = unserialize($this->Session->read('_Token'));

			if ($tokenData['expires'] < time() || $tokenData['key'] !== $token) {
				return false;
			}
		}

		$locked = null;
		$check = $controller->data;
		$token = urldecode($check['_Token']['fields']);

		if (strpos($token, ':')) {
			list($token, $locked) = explode(':', $token, 2);
		}
		unset($check['_Token']);

		$lockedFields = array();
		$fields = Set::flatten($check);
		$fieldList = array_keys($fields);
		$locked = unserialize(str_rot13($locked));
		$multi = array();

		foreach ($fieldList as $i => $key) {
			if (preg_match('/\.\d+$/', $key)) {
				$multi[$i] = preg_replace('/\.\d+$/', '', $key);
				unset($fieldList[$i]);
			}
		}
		if (!empty($multi)) {
			$fieldList += array_unique($multi);
		}

		foreach ($fieldList as $i => $key) {
			$isDisabled = false;
			$isLocked = (is_array($locked) && in_array($key, $locked));

			if (!empty($this->disabledFields)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -618,10 +618,15 @@
 		}
 		unset($check['_Token']);
 
+		$locked = str_rot13($locked);
+		if (preg_match('/(\A|;|{|})O\:[0-9]+/', $locked)) {
+			return false;
+		}
+
 		$lockedFields = array();
 		$fields = Set::flatten($check);
 		$fieldList = array_keys($fields);
-		$locked = unserialize(str_rot13($locked));
+		$locked = unserialize($locked);
 		$multi = array();
 
 		foreach ($fieldList as $i => $key) {
```
