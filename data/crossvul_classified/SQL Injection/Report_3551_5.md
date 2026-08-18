# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 40-68 of the vulnerable file.


	function Nice() {
		return sprintf( '%d', $this->value );
	}
	
	public function scaffoldFormField($title = null, $params = null) {
		return new NumericField($this->name, $title);
	}
	
	/**
	 * Return an encoding of the given value suitable for inclusion in a SQL statement.
	 * If necessary, this should include quotes.
	 */
	function prepValueForDB($value) {
		if($value === true) {
			return 1;
		} if(!$value || !is_numeric($value)) {
			if(strpos($value, '[')===false)
				return '0';
			else
				return addslashes($value);
		} else {
			return addslashes($value);
		}
	}
	
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,9 +57,9 @@
 			if(strpos($value, '[')===false)
 				return '0';
 			else
-				return addslashes($value);
+				return Convert::raw2sql($value);
 		} else {
-			return addslashes($value);
+			return Convert::raw2sql($value);
 		}
 	}
 	
```
