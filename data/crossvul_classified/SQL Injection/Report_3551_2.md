# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 375-415 of the vulnerable file.

			$id = $manipulation[$table]['id'] ? $manipulation[$table]['id'] : $manipulation[$table]['fields']['ID'];;
			if(!$id) user_error("Couldn't find ID in " . var_export($manipulation[$table], true), E_USER_ERROR);
			
			$rid = isset($manipulation[$table]['RecordID']) ? $manipulation[$table]['RecordID'] : $id;

			$newManipulation = array(
				"command" => "insert",
				"fields" => isset($manipulation[$table]['fields']) ? $manipulation[$table]['fields'] : null
			);
			
			if($this->migratingVersion) {
				$manipulation[$table]['fields']['Version'] = $this->migratingVersion;
			}

			// If we haven't got a version #, then we're creating a new version.
			// Otherwise, we're just copying a version to another table
			if(!isset($manipulation[$table]['fields']['Version'])) {
				// Add any extra, unchanged fields to the version record.
				$data = DB::query("SELECT * FROM \"$table\" WHERE \"ID\" = $id")->record();
				if($data) foreach($data as $k => $v) {
					if (!isset($newManipulation['fields'][$k])) $newManipulation['fields'][$k] = "'" . DB::getConn()->addslashes($v) . "'";
				}

				// Set up a new entry in (table)_versions
				$newManipulation['fields']['RecordID'] = $rid;
				unset($newManipulation['fields']['ID']);

				// Create a new version #
				if (isset($version_table[$table])) $nextVersion = $version_table[$table];
				else unset($nextVersion);

				if($rid && !isset($nextVersion)) $nextVersion = DB::query("SELECT MAX(\"Version\") + 1 FROM \"{$baseDataClass}_versions\" WHERE \"RecordID\" = $rid")->value();
				
				$newManipulation['fields']['Version'] = $nextVersion ? $nextVersion : 1;
				
				if($isRootClass) {
					$userID = (Member::currentUser()) ? Member::currentUser()->ID : 0;
					$newManipulation['fields']['AuthorID'] = $userID;
				}
				

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -392,7 +392,7 @@
 				// Add any extra, unchanged fields to the version record.
 				$data = DB::query("SELECT * FROM \"$table\" WHERE \"ID\" = $id")->record();
 				if($data) foreach($data as $k => $v) {
-					if (!isset($newManipulation['fields'][$k])) $newManipulation['fields'][$k] = "'" . DB::getConn()->addslashes($v) . "'";
+					if (!isset($newManipulation['fields'][$k])) $newManipulation['fields'][$k] = "'" . Convert::raw2sql($v) . "'";
 				}
 
 				// Set up a new entry in (table)_versions
```
