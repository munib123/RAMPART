# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5547_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5547_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 388-428 of the vulnerable file.

		return array_merge(parent::getExportableValues(), array(
			'name',
			'description',
			'url',
		));
	}

	/**
	 * Halts bootup and redirects to the site front page
	 * if site is in walled garden mode, no user is logged in,
	 * and the URL is not a public page.
	 *
	 * @link http://docs.elgg.org/Tutorials/WalledGarden
	 *
	 * @return void
	 * @since 1.8.0
	 */
	public function checkWalledGarden() {
		global $CONFIG;

		if ($CONFIG->walled_garden) {
			if ($CONFIG->default_access == ACCESS_PUBLIC) {
				$CONFIG->default_access = ACCESS_LOGGED_IN;
			}
			elgg_register_plugin_hook_handler(
					'access:collections:write',
					'user',
					'_elgg_walled_garden_remove_public_access');

			if (!elgg_is_logged_in()) {
				// hook into the index system call at the highest priority
				elgg_register_plugin_hook_handler('index', 'system', 'elgg_walled_garden_index', 1);

				if (!$this->isPublicPage()) {
					$_SESSION['last_forward_from'] = current_page_url();
					register_error(elgg_echo('loggedinrequired'));
					forward();
				}
			}
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -405,6 +405,11 @@
 	public function checkWalledGarden() {
 		global $CONFIG;
 
+		// command line calls should not invoke the walled garden check
+		if (PHP_SAPI === 'cli') {
+			return;
+		}
+
 		if ($CONFIG->walled_garden) {
 			if ($CONFIG->default_access == ACCESS_PUBLIC) {
 				$CONFIG->default_access = ACCESS_LOGGED_IN;
```
