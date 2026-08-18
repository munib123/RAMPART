# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1703_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1703_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 878-918 of the vulnerable file.

		$this->ar_limit = (int) $value;

		if ($offset != '')
		{
			$this->ar_offset = (int) $offset;
		}

		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * Sets the OFFSET value
	 *
	 * @param	integer	the offset value
	 * @return	object
	 */
	public function offset($offset)
	{
		$this->ar_offset = $offset;
		return $this;
	}

	// --------------------------------------------------------------------

	/**
	 * The "set" function.  Allows key/value pairs to be set for inserting or updating
	 *
	 * @param	mixed
	 * @param	string
	 * @param	boolean
	 * @return	object
	 */
	public function set($key, $value = '', $escape = TRUE)
	{
		$key = $this->_object_to_array($key);

		if ( ! is_array($key))
		{
			$key = array($key => $value);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -895,7 +895,7 @@
 	 */
 	public function offset($offset)
 	{
-		$this->ar_offset = $offset;
+		$this->ar_offset = (int) $offset;
 		return $this;
 	}
 
```
