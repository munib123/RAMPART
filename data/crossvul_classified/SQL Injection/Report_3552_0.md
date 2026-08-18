# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3552_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3552_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 87-127 of the vulnerable file.

	 * @uses Services_JSON
	 *
	 * @param mixed $val
	 * @return string JSON safe string
	 */
	static function raw2json($val) {
		if(function_exists('json_encode')) {
			return json_encode($val);	
		} else {
			require_once(Director::baseFolder() . '/sapphire/thirdparty/json/JSON.php');			
			$json = new Services_JSON();
			return $json->encode($val);
		}
	}
	
	
	static function raw2sql($val) {
		if(is_array($val)) {
			foreach($val as $k => $v) $val[$k] = self::raw2sql($v);
			return $val;
			
		} else {
			return addslashes($val);
		}
	}

	/**
	 * Convert XML to raw text
	 * @uses html2raw()
	 * @todo Currently &#xxx; entries are stripped; they should be converted
	 */
	static function xml2raw($val) {
		if(is_array($val)) {
			foreach($val as $k => $v) $val[$k] = self::xml2raw($v);
			return $val;
			
		} else {

			// More complex text needs to use html2raw instaed
			if(strpos($val,'<') !== false) return self::html2raw($val);
			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,9 +104,8 @@
 		if(is_array($val)) {
 			foreach($val as $k => $v) $val[$k] = self::raw2sql($v);
 			return $val;
-			
-		} else {
-			return addslashes($val);
+		} else {
+			return DB::getConn()->addslashes($val);
 		}
 	}
 
```
