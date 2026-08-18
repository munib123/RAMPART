# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2178_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2178_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 53-93 of the vulnerable file.

    );
    if (
        $data[0] == $_GET['stamp']
        && $data[1] == $_GET['code']
        && $data[2] == $_GET['item_id']
    ) {
        // otv is too old
        if ($data[0] < (time() - $k['otv_expiration_period']) ) {
            $html = "Link is too old!";
        } else {
            $dataItem = $db->queryFirst(
                "SELECT *
                FROM ".$pre."items as i
                INNER JOIN ".$pre."log_items as l ON (l.id_item = i.id)
                WHERE i.id=".intval($_GET['item_id'])."
                AND l.action = 'at_creation'"
            );

            // get data
            $pw = decrypt($dataItem['pw']);
            $label = $dataItem['label'];
            $email = $dataItem['email'];
            $url = $dataItem['url'];
            $description = preg_replace('/(?<!\\r)\\n+(?!\\r)/', '', strip_tags($dataItem['description'], $k['allowedTags']));
            $login = str_replace('"', '&quot;', $dataItem['login']);

            // display data
            $html = "<div style='margin:30px;'>".
            	"<div style='font-size:20px;font-weight:bold;'>Welcome to One-Time item view page.</div>".
            	"<div style='font-style:italic;'>Here are the details of the Item that has been shared to you</div>".
            	"<div style='margin-top:10px;'><table>".
				"<tr><td>Label:</td><td>" . $label . "</td</tr>".
            	"<tr><td>Password:</td><td>" . $pw . "</td</tr>".
            	"<tr><td>Description:</td><td>" . $description . "</td</tr>".
            	"<tr><td>login:</td><td>" . $login . "</td</tr>".
            	"<tr><td>URL:</td><td>" . $url ."</td</tr>".
            	"</table></div>".
            	"<div style='margin-top:30px;'>Copy carefully the data you need. This page is only visible once.</div>".
            	"</div>";

        	// delete entry
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,6 +70,13 @@
 
             // get data
             $pw = decrypt($dataItem['pw']);
+
+        	// get key for original pw
+        	$originalKey = $db->queryFirst('SELECT rand_key FROM `'.$pre.'keys` WHERE `table` LIKE "items" AND `id` ='.intval($_GET['item_id']));
+        	// unsalt previous pw
+        	$pw = substr(decrypt($dataItem['pw']), strlen($originalKey['rand_key']));
+
+
             $label = $dataItem['label'];
             $email = $dataItem['email'];
             $url = $dataItem['url'];
```
