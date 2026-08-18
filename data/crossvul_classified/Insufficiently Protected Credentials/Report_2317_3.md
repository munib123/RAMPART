# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 2317_3
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2317_3`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 20-63 of the vulnerable file.

if(!empty($_POST['do'])) {
	$text = '';
	// Decide What To Do
	switch($_POST['do']) {
		case __('Run', 'wp-dbmanager'):
			check_admin_referer('wp-dbmanager_run');
			$sql_queries2 = trim($_POST['sql_query']);
			$totalquerycount = 0;
			$successquery = 0;
			if($sql_queries2) {
				$sql_queries = array();
				$sql_queries2 = explode("\n", $sql_queries2);
				foreach($sql_queries2 as $sql_query2) {
					$sql_query2 = trim(stripslashes($sql_query2));
					$sql_query2 = preg_replace("/[\r\n]+/", '', $sql_query2);
					if(!empty($sql_query2)) {
						$sql_queries[] = $sql_query2;
					}
				}
				if($sql_queries) {
					foreach($sql_queries as $sql_query) {
						if (preg_match("/^\\s*(insert|update|replace|delete|create|alter) /i",$sql_query)) {
							$run_query = $wpdb->query($sql_query);
							if(!$run_query) {
								$text .= "<p style=\"color: red;\">$sql_query</p>";
							} else {
								$successquery++;
								$text .= "<p style=\"color: green;\">$sql_query</p>";
							}
							$totalquerycount++;
						} elseif (preg_match("/^\\s*(select|drop|show|grant) /i",$sql_query)) {
							$text .= "<p style=\"color: red;\">$sql_query</p>";
							$totalquerycount++;
						}
					}
					$text .= '<p style="color: blue;">'.number_format_i18n($successquery).'/'.number_format_i18n($totalquerycount).' '.__('Query(s) Executed Successfully', 'wp-dbmanager').'</p>';
				} else {
					$text = '<p style="color: red;">'.__('Empty Query', 'wp-dbmanager').'</p>';
				}
			} else {
				$text = '<p style="color: red;">'.__('Empty Query', 'wp-dbmanager').'</p>';
			}
			break;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,18 +37,21 @@
 					}
 				}
 				if($sql_queries) {
-					foreach($sql_queries as $sql_query) {
-						if (preg_match("/^\\s*(insert|update|replace|delete|create|alter) /i",$sql_query)) {
-							$run_query = $wpdb->query($sql_query);
-							if(!$run_query) {
+					foreach( $sql_queries as $sql_query ) {
+						if ( preg_match( "/LOAD_FILE/i", $sql_query ) ) {
+							$text .= "<p style=\"color: red;\">$sql_query</p>";
+							$totalquerycount++;
+						} elseif( preg_match( "/^\\s*(select|drop|show|grant) /i", $sql_query ) ) {
+							$text .= "<p style=\"color: red;\">$sql_query</p>";
+							$totalquerycount++;
+						} else if ( preg_match( "/^\\s*(insert|update|replace|delete|create|alter) /i", $sql_query ) ) {
+							$run_query = $wpdb->query( $sql_query );
+							if( ! $run_query ) {
 								$text .= "<p style=\"color: red;\">$sql_query</p>";
 							} else {
 								$successquery++;
 								$text .= "<p style=\"color: green;\">$sql_query</p>";
 							}
-							$totalquerycount++;
-						} elseif (preg_match("/^\\s*(select|drop|show|grant) /i",$sql_query)) {
-							$text .= "<p style=\"color: red;\">$sql_query</p>";
 							$totalquerycount++;
 						}
 					}
```
