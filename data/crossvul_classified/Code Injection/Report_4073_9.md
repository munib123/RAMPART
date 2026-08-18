# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4073_9
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_9`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 156-196 of the vulnerable file.

		$sql  .= " VALUES (:id,:domain,:enabled,:date_added,:comment,$type);";
		$field = "domain";
	}

	// Prepare SQLite statememt
	$stmt = $db->prepare($sql);

	// Return early if we fail to prepare the SQLite statement
	if(!$stmt)
	{
		echo "Failed to prepare statement for ".$table." table.";
		echo $sql;
		return 0;
	}

	// Loop over rows and inject the entries into the database
	$num = 0;
	foreach($contents as $row)
	{
		// Limit max length for a domain entry to 253 chars
		if(strlen($row[$field]) > 253)
			continue;

		// Bind properties from JSON data
		// Note that only defined above are actually used
		// so even maliciously modified Teleporter files
		// cannot be dangerous in any way
		foreach($row as $key => $value) {
			$type = gettype($value);
			$sqltype=NULL;
			switch($type) {
				case "integer":
					$sqltype = SQLITE3_INTEGER;
				break;
				case "string":
					$sqltype = SQLITE3_TEXT;
				break;
				case "NULL":
					$sqltype = SQLITE3_NULL;
				break;
				default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -173,7 +173,7 @@
 	foreach($contents as $row)
 	{
 		// Limit max length for a domain entry to 253 chars
-		if(strlen($row[$field]) > 253)
+		if(isset($field) && strlen($row[$field]) > 253)
 			continue;
 
 		// Bind properties from JSON data
@@ -196,7 +196,7 @@
 				default:
 					$sqltype = "UNK";
 			}
-			$stmt->bindValue(":".$key, $value, $sqltype);
+			$stmt->bindValue(":".$key, htmlentities($value), $sqltype);
 		}
 
 		if($stmt->execute() && $stmt->reset() && $stmt->clear())
```
