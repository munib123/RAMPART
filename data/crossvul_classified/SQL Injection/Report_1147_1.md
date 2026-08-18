# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1147_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1147_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 31-60 of the vulnerable file.

}
else {
	echo "access denied";
	exit;
}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//delete the call broadcast entry
	if (is_uuid($_GET["id"])) {
		$call_broadcast_uuid = $_GET['id'];
		$array['call_broadcasts'][0]['call_broadcast_uuid'] = $call_broadcast_uuid;
		$array['call_broadcasts'][0]['domain_uuid'] = $_SESSION['domain_uuid'];

		$database = new database;
		$database->app_name = 'call_broadcasts';
		$database->app_uuid = 'efc11f6b-ed73-9955-4d4d-3a1bed75a056';
		$database->delete($array);
		$response = $database->message;
		unset($array);

		message::add($text['message-delete']);
	}

header("Location: call_broadcast.php");
return;

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,6 @@
 		$database->app_name = 'call_broadcasts';
 		$database->app_uuid = 'efc11f6b-ed73-9955-4d4d-3a1bed75a056';
 		$database->delete($array);
-		$response = $database->message;
 		unset($array);
 
 		message::add($text['message-delete']);
```
