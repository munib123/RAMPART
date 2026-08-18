# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3705_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3705_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 16-75 of the vulnerable file.


class Location_Model extends ORM
{
	/**
	 * One-to-many relationship definition
	 * @var array
	 */
	protected $has_many = array('incident', 'media', 'incident_person', 'feed_item', 'reporter', 'checkin');
	
	/**
	 * Many-to-one relationship definition
	 * @var array
	 */
	protected $has_one = array('country');
	
	/**
	 * Database table name
	 * @var string
	 */
	protected $table_name = 'location';
		
	/**
	 * Gets the list of all locations
	 *
	 * @param array $where Key value array with extra predicates for the query
	 * @param int $limit Number of records to fetch
	 * @return Result
	 */
	public static function get_locations($where = array(), $limit = 0)
	{
		// Database table prefix
		$table_prefix = Kohana::config('database.default.table_prefix');
		
		// SQL query
		$sql = 'SELECT id, location_name AS name, country_id, latitude, longitude '
			. 'FROM '.$table_prefix.'location '
			. 'WHERE location_visible = 1 ';
		
		// Check for parameters
		if ( ! empty($where) AND count($where) > 0)
		{
			foreach ($where as $column => $value)
			{
				if ($predicate_items = explode("=", $value))
				{
					if (count($predicate_items) == 2)
					{
						$column = $predicate_items[0];
						$value = $predicate_items[1];
					}
					else
					{
						// Exception handling
						throw new Kohana_Exception('Invalid value in "where" parameter');
					}
				}
				
				$sql .= 'AND '.$column.' = '.$value.' ';	
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,59 +33,6 @@
 	 * @var string
 	 */
 	protected $table_name = 'location';
-		
-	/**
-	 * Gets the list of all locations
-	 *
-	 * @param array $where Key value array with extra predicates for the query
-	 * @param int $limit Number of records to fetch
-	 * @return Result
-	 */
-	public static function get_locations($where = array(), $limit = 0)
-	{
-		// Database table prefix
-		$table_prefix = Kohana::config('database.default.table_prefix');
-		
-		// SQL query
-		$sql = 'SELECT id, location_name AS name, country_id, latitude, longitude '
-			. 'FROM '.$table_prefix.'location '
-			. 'WHERE location_visible = 1 ';
-		
-		// Check for parameters
-		if ( ! empty($where) AND count($where) > 0)
-		{
-			foreach ($where as $column => $value)
-			{
-				if ($predicate_items = explode("=", $value))
-				{
-					if (count($predicate_items) == 2)
-					{
-						$column = $predicate_items[0];
-						$value = $predicate_items[1];
-					}
-					else
-					{
-						// Exception handling
-						throw new Kohana_Exception('Invalid value in "where" parameter');
-					}
-				}
-				
-				$sql .= 'AND '.$column.' = '.$value.' ';	
-			}
-		}
-		
-		// Order the records by database ID
-		$sql .= 'ORDER BY id DESC ';
-		
-		// Check if the record limit has been specified
-		if ((int)$limit > 0)
-		{
-			$sql .= 'LIMIT 0, '.$limit;
-		}
-		
-		$db = new Database();
-		return $db->query($sql);
-	}
 	
 	/**
 	 * Checks if a location id exists in the database
```
