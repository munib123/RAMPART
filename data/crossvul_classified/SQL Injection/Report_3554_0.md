# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3554_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3554_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 25-65 of the vulnerable file.

	 * Find the given folder or create it both as {@link Folder} database records
	 * and on the filesystem. If necessary, creates parent folders as well.
	 * 
	 * @param $folderPath string Absolute or relative path to the file.
	 *  If path is relative, its interpreted relative to the "assets/" directory.
	 * @return Folder
	 */
	static function findOrMake($folderPath) {
		// Create assets directory, if it is missing
		if(!file_exists(ASSETS_PATH)) Filesystem::makeFolder(ASSETS_PATH);

		$folderPath = trim(Director::makeRelative($folderPath));
		// replace leading and trailing slashes
		$folderPath = preg_replace('/^\/?(.*)\/?$/', '$1', $folderPath);
		$parts = explode("/",$folderPath);

		$parentID = 0;
		$item = null;
		foreach($parts as $part) {
			if(!$part) continue; // happens for paths with a trailing slash
			$item = DataObject::get_one("Folder", "\"Name\" = '$part' AND \"ParentID\" = $parentID");
			if(!$item) {
				$item = new Folder();
				$item->ParentID = $parentID;
				$item->Name = $part;
				$item->Title = $part;
				$item->write();
			}
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,14 @@
 		$item = null;
 		foreach($parts as $part) {
 			if(!$part) continue; // happens for paths with a trailing slash
-			$item = DataObject::get_one("Folder", "\"Name\" = '$part' AND \"ParentID\" = $parentID");
+			$item = DataObject::get_one(
+				"Folder", 
+				sprintf(
+					"\"Name\" = '%s' AND \"ParentID\" = %d",
+					Convert::raw2sql($part), 
+					(int)$parentID
+				)
+			);
 			if(!$item) {
 				$item = new Folder();
 				$item->ParentID = $parentID;
```
