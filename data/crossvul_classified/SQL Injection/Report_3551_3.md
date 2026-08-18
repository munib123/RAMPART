# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 42-78 of the vulnerable file.

	public function scaffoldFormField($title = null, $params = null) {
		return new CheckboxField($this->name, $title);
	}
	
	public function scaffoldSearchField($title = null) {
		$anyText = _t('Boolean.ANY', 'Any');
		$source = array(
			1 => _t('Boolean.YES', 'Yes'),
			0 => _t('Boolean.NO', 'No')
		);
		
		return new DropdownField($this->name, $title, $source, '', null, "($anyText)");
	}

	/**
	 * Return an encoding of the given value suitable for inclusion in a SQL statement.
	 * If necessary, this should include quotes.
	 */
	function prepValueForDB($value) {
		if(strpos($value, '[')!==false)
			return addslashes($value);
		else {		
			if($value && strtolower($value) != 'f') {
				return "'1'";
			} else {
				return "'0'";
			}
		}
	}

	function nullValue() {
		return "'0'";
	}
	
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,7 +59,7 @@
 	 */
 	function prepValueForDB($value) {
 		if(strpos($value, '[')!==false)
-			return addslashes($value);
+			return Convert::raw2sql($value);
 		else {		
 			if($value && strtolower($value) != 'f') {
 				return "'1'";
```
