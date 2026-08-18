# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4073_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_6`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 144-184 of the vulnerable file.

	// Return early if we failed to prepare the SQLite statement
	if(!$stmt)
	{
		if($returnnum)
			return 0;
		else
			return "Error: Failed to prepare statement for $table table (type = $type, field = $field).";
	}

	// Loop over domains and inject the lines into the database
	$num = 0;
	foreach($domains as $domain)
	{
		// Limit max length for a domain entry to 253 chars
		if(strlen($domain) > 253)
			continue;

		if($wildcardstyle)
			$domain = "(\\.|^)".str_replace(".","\\.",$domain)."$";

		$stmt->bindValue(":$field", $domain, SQLITE3_TEXT);
		if($bindcomment) {
			$stmt->bindValue(":comment", $comment, SQLITE3_TEXT);
		}

		if($stmt->execute() && $stmt->reset())
			$num++;
		else
		{
			$stmt->close();
			if($returnnum)
				return $num;
			else
			{
				if($num === 1)
					$plural = "";
				else
					$plural = "s";
				return "Error: ".$db->lastErrorMsg().", added ".$num." domain".$plural;
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,9 +161,9 @@
 		if($wildcardstyle)
 			$domain = "(\\.|^)".str_replace(".","\\.",$domain)."$";
 
-		$stmt->bindValue(":$field", $domain, SQLITE3_TEXT);
+		$stmt->bindValue(":$field", htmlentities($domain), SQLITE3_TEXT);
 		if($bindcomment) {
-			$stmt->bindValue(":comment", $comment, SQLITE3_TEXT);
+			$stmt->bindValue(":comment", htmlentities($comment), SQLITE3_TEXT);
 		}
 
 		if($stmt->execute() && $stmt->reset())
```
