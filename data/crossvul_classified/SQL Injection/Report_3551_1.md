# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 330-370 of the vulnerable file.

	
	public function fieldList($table) {
		$fields = DB::query("SHOW FULL FIELDS IN \"$table\"");
		foreach($fields as $field) {
			$fieldSpec = $field['Type'];
			if(!$field['Null'] || $field['Null'] == 'NO') {
				$fieldSpec .= ' not null';
			}
			
			if($field['Collation'] && $field['Collation'] != 'NULL') {
				// Cache collation info to cut down on database traffic
				if(!isset(self::$_cache_collation_info[$field['Collation']])) {
					self::$_cache_collation_info[$field['Collation']] = DB::query("SHOW COLLATION LIKE '$field[Collation]'")->record();
				}
				$collInfo = self::$_cache_collation_info[$field['Collation']];
				$fieldSpec .= " character set $collInfo[Charset] collate $field[Collation]";
			}
			
			if($field['Default'] || $field['Default'] === "0") {
				if(is_numeric($field['Default']))
					$fieldSpec .= " default " . addslashes($field['Default']);
				else
					$fieldSpec .= " default '" . addslashes($field['Default']) . "'";
			}
			if($field['Extra']) $fieldSpec .= " $field[Extra]";
			
			$fieldList[$field['Field']] = $fieldSpec;
		}
		return $fieldList;
	}
	
	/**
	 * Create an index on a table.
	 * 
	 * @param string $tableName The name of the table.
	 * @param string $indexName The name of the index.
	 * @param string $indexSpec The specification of the index, see {@link SS_Database::requireIndex()} for more details.
	 */
	public function createIndex($tableName, $indexName, $indexSpec) {
		$this->query("ALTER TABLE \"$tableName\" ADD " . $this->getIndexSqlDefinition($indexName, $indexSpec));
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -347,9 +347,9 @@
 			
 			if($field['Default'] || $field['Default'] === "0") {
 				if(is_numeric($field['Default']))
-					$fieldSpec .= " default " . addslashes($field['Default']);
+					$fieldSpec .= " default " . Convert::raw2sql($field['Default']);
 				else
-					$fieldSpec .= " default '" . addslashes($field['Default']) . "'";
+					$fieldSpec .= " default '" . Convert::raw2sql($field['Default']) . "'";
 			}
 			if($field['Extra']) $fieldSpec .= " $field[Extra]";
 			
@@ -862,8 +862,7 @@
 	}
 	
 	/*
-	 * This will return text which has been escaped in a database-friendly manner
-	 * Using PHP's addslashes method won't work in MSSQL
+	 * This will return text which has been escaped in a database-friendly manner.
 	 */
 	function addslashes($value){
 		return mysql_real_escape_string($value, $this->dbConn);
```
