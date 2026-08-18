# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 3388_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3388_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 2286-2326 of the vulnerable file.

			$this->track("bigtree_templates",$template["id"],"deleted");
			return true;
		}

		/*
			Function: deleteUser
				Deletes a user.
				Checks for developer access.

			Parameters:
				id - The user id to delete.

			Returns:
				true if successful. false if the logged in user does not have permission to delete the user.
		*/

		function deleteUser($id) {
			$id = sqlescape($id);
			// If this person has higher access levels than the person trying to update them, fail.
			$current = static::getUser($id);
			if ($current["level"] > $this->Level) {
				return false;
			}

			sqlquery("DELETE FROM bigtree_users WHERE id = '$id'");
			$this->track("bigtree_users",$id,"deleted");

			return true;
		}

		/*
			Function: disconnectGoogleAnalytics
				Turns of Google Analytics settings in BigTree and deletes cached information.
		*/

		function disconnectGoogleAnalytics() {
			unlink(SERVER_ROOT."cache/analytics.json");
			sqlquery("UPDATE bigtree_pages SET ga_page_views = NULL");
			sqlquery("DELETE FROM bigtree_caches WHERE identifier = 'org.bigtreecms.api.analytics.google'");
			static::growl("Analytics","Disconnected");
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2303,7 +2303,8 @@
 			$id = sqlescape($id);
 			// If this person has higher access levels than the person trying to update them, fail.
 			$current = static::getUser($id);
-			if ($current["level"] > $this->Level) {
+
+			if ($current["level"] > $this->Level || $id == $this->ID) {
 				return false;
 			}
 
```
