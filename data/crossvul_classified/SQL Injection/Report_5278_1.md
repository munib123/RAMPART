# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5278_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5278_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1088-1128 of the vulnerable file.

	* Returns an error message from the database server.  This is intended to be
	* used by the implementers of the database wrapper, so that certain
	* cryptic error messages can be reworded.
	* @return string
	*/
	abstract function error();

	/**
	* Checks whether the database connection has experienced an error.
	* @return bool
	*/
	abstract function inError();

	/**
	 * Unescape a string based on the database connection
	 * @param $string
	 * @return string
	 */
	abstract function escapeString($string);

	/**
	 * Create a SQL "limit" phrase
	 *
	 * @param  $num
	 * @param  $offset
	 * @return string
	 */
	function limit($num, $offset) {
	   return ' LIMIT ' . $offset . ',' . $num . ' ';
	}

	/**
	* Select an array of arrays
	*
	* Selects a set of arrays from the database.  Because of the way
	* Exponent handles objects and database tables, this is akin to
	* SELECTing a set of records from a database table.  Returns an
	* array of arrays, in any random order.
	*
	* @param string $table The name of the table/object to look at
	* @param string $where Criteria used to narrow the result set.  If this
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1105,6 +1105,21 @@
 	 */
 	abstract function escapeString($string);
 
+    /**
+   	 * Unescape a string based on the database connection
+   	 * @param $string
+   	 * @return string
+   	 */
+   	function injectProof($string) {
+   	    $quotes = substr_count("'", $string);
+        if ($quotes % 2 != 0)
+            $string = $this->escapeString($string);
+        $dquotes = substr_count('"', $string);
+        if ($dquotes % 2 != 0)
+            $string = $this->escapeString($string);
+        return $string;
+    }
+
 	/**
 	 * Create a SQL "limit" phrase
 	 *
```
