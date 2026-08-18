# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3700_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3700_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 85-125 of the vulnerable file.


	/**
	 * Given a validation object, updates the settings table
	 * with the values assigned to its properties
	 *
	 * @param Validation $settings Validation object
	 */
	public static function save_all(Validation $settings)
	{
		// Get all the settings
		$all_settings = self::get_array();

		// Settings update query
		$query = sprintf("UPDATE `%ssettings` SET `value` = CASE `key` ", 
		    Kohana::config('database.default.table_prefix'));

		// Used for building the query clauses for the final query
		$values = array();
		$keys = array();
		
		// List of value to skip
		$skip = array('api_live');
		foreach ($settings as $key => $value)
		{
			// If an item has been marked for skipping or is a 
			// non-existent setting, skip current iteration
			if (in_array($key, $skip) OR empty($key) OR ! array_key_exists($key, $all_settings))
				continue;

			// Check for the timezone
			if ($key === 'timezone' AND $value == 0)
			{
				$value = NULL;
			}

			$keys[] = sprintf("'%s'", $key);
			$values[] = sprintf("WHEN '%s' THEN '%s' ", $key, $value);
		}
		
		// Modification date
		$keys[] = "'date_modify'";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,6 +102,9 @@
 		$values = array();
 		$keys = array();
 		
+		// Modification date
+		$settings['date_modify'] = date("Y-m-d H:i:s",time());
+		
 		// List of value to skip
 		$skip = array('api_live');
 		foreach ($settings as $key => $value)
@@ -116,19 +119,17 @@
 			{
 				$value = NULL;
 			}
+			
 
-			$keys[] = sprintf("'%s'", $key);
-			$values[] = sprintf("WHEN '%s' THEN '%s' ", $key, $value);
+			$keys[] = Database::instance()->escape($key);
+			$values[] = sprintf("WHEN %s THEN %s ", Database::instance()->escape($key), Database::instance()->escape($value));
 		}
-		
-		// Modification date
-		$keys[] = "'date_modify'";
-		$values[] = sprintf("WHEN 'date_modify' THEN '%s' ", date("Y-m-d H:i:s",time()));
 		
 		// Construct the final query
 		$query .= implode(" ", $values)."END WHERE `key` IN (%s)";
 		$query = sprintf($query, implode(",", $keys));
 		
+
 		// Performa batch update
 		Database::instance()->query($query);
 	}
```
