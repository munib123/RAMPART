# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3750_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

*/

//no apps or filesystem
$RUNTIME_NOSETUPFS=true;

 

// Check if we are a user
OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('bookmarks');

$CONFIG_DBTYPE = OCP\Config::getSystemValue( "dbtype", "sqlite" );
if( $CONFIG_DBTYPE == 'sqlite' or $CONFIG_DBTYPE == 'sqlite3' ){
	$_ut = "strftime('%s','now')";
} elseif($CONFIG_DBTYPE == 'pgsql') {
	$_ut = 'date_part(\'epoch\',now())::integer';
} else {
	$_ut = "UNIX_TIMESTAMP()";
}

$bookmark_id = (int)$_GET["id"];

$query = OCP\DB::prepare("
	UPDATE *PREFIX*bookmarks
	SET url = ?, title =?, lastmodified = $_ut
	WHERE id = $bookmark_id
	");

$params=array(
	htmlspecialchars_decode($_GET["url"]),
	htmlspecialchars_decode($_GET["title"]),
	);
$query->execute($params);

# Remove old tags and insert new ones.
$query = OCP\DB::prepare("
	DELETE FROM *PREFIX*bookmarks_tags
	WHERE bookmark_id = $bookmark_id
	");

$query->execute();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
 	$_ut = "UNIX_TIMESTAMP()";
 }
 
-$bookmark_id = (int)$_GET["id"];
+$bookmark_id = (int)$_POST["id"];
 
 $query = OCP\DB::prepare("
 	UPDATE *PREFIX*bookmarks
@@ -48,8 +48,8 @@
 	");
 
 $params=array(
-	htmlspecialchars_decode($_GET["url"]),
-	htmlspecialchars_decode($_GET["title"]),
+	htmlspecialchars_decode($_POST["url"]),
+	htmlspecialchars_decode($_POST["title"]),
 	);
 $query->execute($params);
 
@@ -67,7 +67,7 @@
 	VALUES (?, ?)
 	");
 	
-$tags = explode(' ', urldecode($_GET["tags"]));
+$tags = explode(' ', urldecode($_POST["tags"]));
 foreach ($tags as $tag) {
 	if(empty($tag)) {
 		//avoid saving blankspaces
```
