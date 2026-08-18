# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5774_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5774_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 110-150 of the vulnerable file.

				include "../templates/basic/_404.php";
				$bigtree["content"] = ob_get_clean();
				ob_start();
				include "../templates/layouts/".$bigtree["layout"].".php";
				die();
			}
		}
		
		/*
			Function: checkOldRoutes
				Checks the old route table, redirects if the page is found.
			
			Parameters:
				path - An array of routes
		*/
		
		function checkOldRoutes($path) {
			$found = false;
			$x = count($path);
			while ($x) {
				$f = sqlfetch(sqlquery("SELECT * FROM bigtree_route_history WHERE old_route = '".implode("/",array_slice($path,0,$x))."'"));
				if ($f) {
					$old = $f["old_route"];
					$new = $f["new_route"];
					$found = true;
					break;
				}
				$x--;
			}
			// If it's in the old routing table, send them to the new page.
			if ($found) {
				$new_url = $new.substr($_GET["bigtree_htaccess_url"],strlen($old));
				BigTree::redirect(WWW_ROOT.$new_url,"301");
			}
		}
		
		/*
			Function: decodeCallouts
				Turns the JSON callout data into a PHP array of callouts with links being translated into front-end readable links.
				This function is called by BigTree's router and is generally not a function needed to end users.
			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,7 +127,7 @@
 			$found = false;
 			$x = count($path);
 			while ($x) {
-				$f = sqlfetch(sqlquery("SELECT * FROM bigtree_route_history WHERE old_route = '".implode("/",array_slice($path,0,$x))."'"));
+				$f = sqlfetch(sqlquery("SELECT * FROM bigtree_route_history WHERE old_route = '".sqlescape(implode("/",array_slice($path,0,$x)))."'"));
 				if ($f) {
 					$old = $f["old_route"];
 					$new = $f["new_route"];
```
