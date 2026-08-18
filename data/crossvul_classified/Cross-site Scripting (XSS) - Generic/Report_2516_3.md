# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2516_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2516_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 114-154 of the vulnerable file.

	}
} 
else {	
	// Show the result form	
	//initialising the default values
	$wheretosearch = 0;
	$item = "";
	$g_id = "";
	$resultquery = "";
	$displaysearchfield = "";
	
	//xmlstoresearch will contain the query in xml format (to store and load search)
	$xmlstoresearch = "";
	
	// if a search term was entered make the regexp and build the "LIKE" query	
	if ($_POST['begriff']!=""){
		if (isset($_POST['username']))	$wheretosearch += 1; 
		if (isset($_POST['realname']))  $wheretosearch += 2;
		if (isset($_POST['email']))		$wheretosearch += 4;
		
		//$item = $admin->add_slashes($admin->get_post('begriff'));
		
		$xmlstoresearch .= "<searchterm>".$admin->add_slashes($admin->get_post('begriff'))."</searchterm>";
		$item = str_replace("*", '%', $admin->add_slashes($admin->get_post('begriff')));
		
	
		switch($wheretosearch) {
			case 1:	
				$resultquery = "(username LIKE '".$item."'"; 
				$xmlstoresearch .= "<username>true</username>";
				$displaysearchfield .= $MOD_USER_SEARCH['USER_NAME'];
				break;
			case 2:	
				$resultquery = "(display_name LIKE '".$item."'"; 
				$xmlstoresearch .= "<realname>true</realname>";
				$displaysearchfield .= $MOD_USER_SEARCH['REAL_NAME'];
				break;
			case 3:	
				$resultquery = "(username LIKE '".$item."' OR display_name LIKE '".$item."'"; 
				$xmlstoresearch .= "<username>true</username><realname>true</realname>";				
				$displaysearchfield .= $MOD_USER_SEARCH['USER_NAME'].", ".$MOD_USER_SEARCH['REAL_NAME'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -131,10 +131,11 @@
 		if (isset($_POST['realname']))  $wheretosearch += 2;
 		if (isset($_POST['email']))		$wheretosearch += 4;
 		
-		//$item = $admin->add_slashes($admin->get_post('begriff'));
-		
-		$xmlstoresearch .= "<searchterm>".$admin->add_slashes($admin->get_post('begriff'))."</searchterm>";
-		$item = str_replace("*", '%', $admin->add_slashes($admin->get_post('begriff')));
+		$item_raw = $admin->add_slashes($admin->get_post('begriff'));
+		$item = $database->escapeString($item_raw);
+		
+		$xmlstoresearch .= "<searchterm>".$item."</searchterm>";
+		$item = str_replace("*", '%', $item);
 		
 	
 		switch($wheretosearch) {
@@ -191,14 +192,15 @@
 			$xmlstoresearch .= "<before>true</before>";
 		}
 		// convert date to timestamp format to compare
-		$resultquery .= jscalendar_to_timestamp($_POST['comp_date'],TIMEZONE);
-		$xmlstoresearch .= "<date>".jscalendar_to_timestamp($_POST['comp_date'],TIMEZONE)."</date>";
+		$resultquery .= $database->escapeString(jscalendar_to_timestamp($_POST['comp_date'],TIMEZONE));
+		
+		$xmlstoresearch .= "<date>".$database->escapeString(jscalendar_to_timestamp($_POST['comp_date'],TIMEZONE))."</date>";
 		$xmlstoresearch .= "</datelastlogin>";
 		}
 	
 	// if a group was choosen modify the sql query
 	if (isset($_POST['groups'])&&($_POST['groups']!="-1")) {
-		$g_id = $_POST['groups'];
+		$g_id = $database->escapeString($_POST['groups']);
 		if ($resultquery!="") $resultquery .= ") AND";
 		$g_id = str_replace(",", '%', $g_id);
 		$resultquery .= " (groups_id LIKE '%$g_id%'";
@@ -237,7 +239,7 @@
 		if ($wheretosearch != 0) {
 			// display if a search term was entered
 			$tpl->set_var('SEARCH_ITEM_RESULT', $MOD_USER_SEARCH['SEARCH_ITEM_RESULT']);
-			$tpl->set_var('BEGRIFF', $admin->add_slashes($admin->get_post('begriff')));
+			$tpl->set_var('BEGRIFF',htmlspecialchars($admin->get_post('begriff'),ENT_QUOTES, "UTF-8"));
 			$tpl->set_var('SEARCH_FIELD_RESULT', $MOD_USER_SEARCH['SEARCH_FIELD_RESULT']);
 			$tpl->set_var('DISPLAYSEARCHFIELD', $displaysearchfield);
 			$tpl->parse('searchterm_block_handle', 'searchterm_block');
```
