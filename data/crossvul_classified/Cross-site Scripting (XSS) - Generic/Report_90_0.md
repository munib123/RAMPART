# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 90_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `90_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 8402-8447 of the vulnerable file.

			$id = sqlescape($id);
			$changes = BigTree::json($changes,true);
			$mtm_changes = BigTree::json($mtm_changes,true);
			$tags_changes = BigTree::json($tags_changes,true);

			sqlquery("UPDATE bigtree_pending_changes SET changes = '$changes', mtm_changes = '$mtm_changes', tags_changes = '$tags_changes', date = NOW(), user = '".$this->ID."' WHERE id = '$id'");
			$this->track("bigtree_pending_changes",$id,"updated");
		}

		/*
			Function: updateProfile
				Updates a user's name, company, digest setting, and (optionally) password.

			Parameters:
				data - Array containing name / company / daily_digest / password.
		*/

		function updateProfile($data) {
			global $bigtree;

			foreach ($data as $key => $val) {
				if (substr($key,0,1) != "_" && !is_array($val)) {
					$$key = sqlescape($val);
				}
			}

			$id = sqlescape($this->ID);

			if ($data["password"]) {
				$phpass = new PasswordHash($bigtree["config"]["password_depth"], TRUE);
				$password = sqlescape($phpass->HashPassword($data["password"]));
				sqlquery("UPDATE bigtree_users SET `password` = '$password', `name` = '$name', `company` = '$company', `daily_digest` = '$daily_digest' WHERE id = '$id'");
			} else {
				sqlquery("UPDATE bigtree_users SET `name` = '$name', `company` = '$company', `daily_digest` = '$daily_digest' WHERE id = '$id'");
			}
		}

		/*
			Function: updateResource
				Updates a resource.

			Parameters:
				id - The id of the resource.
				attributes - A key/value array of fields to update.
		*/

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8419,12 +8419,9 @@
 		function updateProfile($data) {
 			global $bigtree;
 
-			foreach ($data as $key => $val) {
-				if (substr($key,0,1) != "_" && !is_array($val)) {
-					$$key = sqlescape($val);
-				}
-			}
-
+			$name = sqlescape(htmlspecialchars($data["name"]));
+			$company = sqlescape(htmlspecialchars($data["company"]));
+			$daily_digest = $data["daily_digest"] ? "on" : "";
 			$id = sqlescape($this->ID);
 
 			if ($data["password"]) {
```
