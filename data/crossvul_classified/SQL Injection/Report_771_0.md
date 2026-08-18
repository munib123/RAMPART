# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 771_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `771_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 483-523 of the vulnerable file.

			'boolean' => PDO::PARAM_BOOL,
			'string' => PDO::PARAM_STR,
			'object' => PDO::PARAM_STR,
			'resource' => PDO::PARAM_LOB
		];

		if ($type === 'boolean')
		{
			$value = ($value ? '1' : '0');
		}
		elseif ($type === 'NULL')
		{
			$value = null;
		}

		return [$value, $map[ $type ]];
	}

	protected function columnQuote($string)
	{
		if (strpos($string, '.') !== false)
		{
			return '"' . $this->prefix . str_replace('.', '"."', $string) . '"';
		}

		return '"' . $string . '"';
	}

	protected function columnPush(&$columns, &$map, $root, $is_join = false)
	{
		if ($columns === '*')
		{
			return $columns;
		}

		$stack = [];

		if (is_string($columns))
		{
			$columns = [$columns];
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -500,6 +500,11 @@
 
 	protected function columnQuote($string)
 	{
+		if (!preg_match('/^[a-zA-Z0-9]+(\.?[a-zA-Z0-9]+)?$/i', $string))
+		{
+			throw new InvalidArgumentException("Incorrect column name \"$string\"");
+		}
+
 		if (strpos($string, '.') !== false)
 		{
 			return '"' . $this->prefix . str_replace('.', '"."', $string) . '"';
```
