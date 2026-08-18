# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4519_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4519_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 486-526 of the vulnerable file.

						array_merge([$parts[1],NULL],$jar));
				}
				unset($_COOKIE[$parts[1]]);
			}
		}
		elseif ($parts[0]=='SESSION') {
			if (!headers_sent() && session_status()!=PHP_SESSION_ACTIVE)
				session_start();
			if (empty($parts[1])) {
				// End session
				session_unset();
				session_destroy();
				$this->clear('COOKIE.'.session_name());
			}
			$this->sync('SESSION');
		}
		if (!isset($parts[1]) && array_key_exists($parts[0],$this->init))
			// Reset global to default value
			$this->hive[$parts[0]]=$this->init[$parts[0]];
		else {
			eval('unset('.$this->compile('@this->hive.'.$key).');');
			if ($parts[0]=='SESSION') {
				session_commit();
				session_start();
			}
			if ($cache->exists($hash=$this->hash($key).'.var'))
				// Remove from cache
				$cache->clear($hash);
		}
	}

	/**
	*	Return TRUE if hive variable is 'on'
	*	@return bool
	*	@param $key string
	**/
	function checked($key) {
		$ref=&$this->ref($key);
		return $ref=='on';
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -503,6 +503,8 @@
 			// Reset global to default value
 			$this->hive[$parts[0]]=$this->init[$parts[0]];
 		else {
+			// Ensure we have no code injection
+			$key=preg_replace('/(\)\W*\w+.*$)/','',$key);
 			eval('unset('.$this->compile('@this->hive.'.$key).');');
 			if ($parts[0]=='SESSION') {
 				session_commit();
@@ -2963,13 +2965,11 @@
 	*	@param $str string
 	**/
 	function token($str) {
-		$fw=$this->fw;
-		$str=trim(preg_replace('/\{\{(.+?)\}\}/s',trim('\1'),
-			$fw->compile($str)));
+		$str=trim(preg_replace('/\{\{(.+?)\}\}/s','\1',$this->fw->compile($str)));
 		if (preg_match('/^(.+)(?<!\|)\|((?:\h*\w+(?:\h*[,;]?))+)$/s',
 			$str,$parts)) {
 			$str=trim($parts[1]);
-			foreach ($fw->split(trim($parts[2],"\xC2\xA0")) as $func)
+			foreach ($this->fw->split(trim($parts[2],"\xC2\xA0")) as $func)
 				$str=((empty($this->filter[$cmd=$func]) &&
 					function_exists($cmd)) ||
 					is_string($cmd=$this->filter($func)))?
```
