# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 65-105 of the vulnerable file.

	 	if($data['any']) $keywords .= ' ' . $data['any'];
	 	if($data['-']) $keywords .= " -" . ereg_replace(" +", " -", trim($data['-']));
	 	$keywords = trim($keywords);
	 	
	 	// This means that they want to just find pages where there's *no* match
	 	
	 	if($keywords[0] == '-') {
	 		$keywords = $data['-'];
	 		$invertedMatch = true;
	 	}

	 	
	 	// Limit search to various sections
	 	if($_REQUEST['OnlyShow']) {
	 		$pageList = array();

			// Find the associated pages	 		
	 		foreach($_REQUEST['OnlyShow'] as $section => $checked) {
	 			$items = explode(",", $section);
	 			foreach($items as $item) {
	 				$page = DataObject::get_one('SiteTree', "\"URLSegment\" = '" . DB::getConn()->addslashes($item) . "'");
	 				$pageList[] = $page->ID;
	 				if(!$page) user_error("Can't find a page called '$item'", E_USER_WARNING);
	 				$page->loadDescendantIDListInto($pageList);
	 			}
	 		}	
	 		$contentFilter = "\"ID\" IN (" . implode(",", $pageList) . ")";
	 		
	 		// Find the files associated with those pages
	 		$fileList = DB::query("SELECT \"FileID\" FROM \"Page_ImageTracking\" WHERE \"PageID\" IN (" . implode(",", $pageList) . ")")->column();
	 		if($fileList) $fileFilter = "\"ID\" IN (" . implode(",", $fileList) . ")";
	 		else $fileFilter = " 1 = 2 ";
	 	}
	 	
	 	if($data['From']) {
	 		$filter .= ($filter?" AND":"") . " \"LastEdited\" >= '$data[From]'";
	 	}
	 	if($data['To']) {
	 		$filter .= ($filter?" AND":"") . " \"LastEdited\" <= '$data[To]'";
	 	}
	 	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,7 @@
 	 		foreach($_REQUEST['OnlyShow'] as $section => $checked) {
 	 			$items = explode(",", $section);
 	 			foreach($items as $item) {
-	 				$page = DataObject::get_one('SiteTree', "\"URLSegment\" = '" . DB::getConn()->addslashes($item) . "'");
+	 				$page = DataObject::get_one('SiteTree', "\"URLSegment\" = '" . Convert::raw2sql($item) . "'");
 	 				$pageList[] = $page->ID;
 	 				if(!$page) user_error("Can't find a page called '$item'", E_USER_WARNING);
 	 				$page->loadDescendantIDListInto($pageList);
```
