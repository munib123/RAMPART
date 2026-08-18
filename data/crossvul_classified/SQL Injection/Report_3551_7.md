# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 60-100 of the vulnerable file.

			if(!file_exists($item->getFullPath())) {
				Filesystem::makeFolder($item->getFullPath());
			}
			$parentID = $item->ID;
		}

		return $item;
	}
	
	/**
	 * Syncronise the file database with the actual content of the assets folder
	 */
	function syncChildren() {
		$parentID = (int)$this->ID; // parentID = 0 on the singleton, used as the 'root node';
		$added = 0;
		$deleted = 0;

		// First, merge any children that are duplicates
		$duplicateChildrenNames = DB::query("SELECT \"Name\" FROM \"File\" WHERE \"ParentID\" = $parentID GROUP BY \"Name\" HAVING count(*) > 1")->column();
		if($duplicateChildrenNames) foreach($duplicateChildrenNames as $childName) {
			$childName = DB::getConn()->addslashes($childName);
			// Note, we do this in the database rather than object-model; otherwise we get all sorts of problems about deleting files
			$children = DB::query("SELECT \"ID\" FROM \"File\" WHERE \"Name\" = '$childName' AND \"ParentID\" = $parentID")->column();
			if($children) {
				$keptChild = array_shift($children);
				foreach($children as $removedChild) {
					DB::query("UPDATE \"File\" SET \"ParentID\" = $keptChild WHERE \"ParentID\" = $removedChild");
					DB::query("DELETE FROM \"File\" WHERE \"ID\" = $removedChild");
				}
			} else {
				user_error("Inconsistent database issue: SELECT ID FROM \"File\" WHERE Name = '$childName' AND ParentID = $parentID should have returned data", E_USER_WARNING);
			}
		}

		
		// Get index of database content
		// We don't use DataObject so that things like subsites doesn't muck with this.
		$dbChildren = DB::query("SELECT * FROM \"File\" WHERE \"ParentID\" = $parentID");
		$hasDbChild = array();
		if($dbChildren) {
			foreach($dbChildren as $dbChild) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,7 @@
 		// First, merge any children that are duplicates
 		$duplicateChildrenNames = DB::query("SELECT \"Name\" FROM \"File\" WHERE \"ParentID\" = $parentID GROUP BY \"Name\" HAVING count(*) > 1")->column();
 		if($duplicateChildrenNames) foreach($duplicateChildrenNames as $childName) {
-			$childName = DB::getConn()->addslashes($childName);
+			$childName = Convert::raw2sql($childName);
 			// Note, we do this in the database rather than object-model; otherwise we get all sorts of problems about deleting files
 			$children = DB::query("SELECT \"ID\" FROM \"File\" WHERE \"Name\" = '$childName' AND \"ParentID\" = $parentID")->column();
 			if($children) {
@@ -184,10 +184,10 @@
 		if(Member::currentUser()) $ownerID = Member::currentUser()->ID;
 		else $ownerID = 0;
 		
-		$filename = DB::getConn()->addslashes($this->Filename . $name);
+		$filename = Convert::raw2sql($this->Filename . $name);
 		if($className == 'Folder' ) $filename .= '/';
 
-		$name = DB::getConn()->addslashes($name);
+		$name = Convert::raw2sql($name);
 		
 		DB::query("INSERT INTO \"File\" 
 			(\"ClassName\", \"ParentID\", \"OwnerID\", \"Name\", \"Filename\", \"Created\", \"LastEdited\", \"Title\")
```
