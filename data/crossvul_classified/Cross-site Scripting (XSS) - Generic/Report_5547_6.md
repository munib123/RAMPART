# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5547_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5547_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 286-329 of the vulnerable file.

			return false;
		}

		$db_prefix = elgg_get_config('dbprefix');
		// need to remove all namespaced private settings.
		$us_prefix = elgg_namespace_plugin_private_setting('user_setting', '', $this->getID());
		$is_prefix = elgg_namespace_plugin_private_setting('internal', '', $this->getID());

		// Get private settings for user
		$q = "SELECT * FROM {$db_prefix}private_settings
			WHERE entity_guid = $this->guid
			AND name NOT LIKE '$us_prefix%'
			AND name NOT LIKE '$is_prefix%'";

		$private_settings = $this->getDatabase()->getData($q);

		if ($private_settings) {
			$return = array();

			foreach ($private_settings as $setting) {
				$name = substr($setting->name, $ps_prefix_len);
				$value = $setting->value;

				$return[$name] = $value;
			}

			return $return;
		}

		return false;
	}

	/**
	 * Set a plugin setting for the plugin
	 *
	 * @todo This will only work once the plugin has a GUID.
	 *
	 * @param string $name  The name to set
	 * @param string $value The value to set
	 *
	 * @return bool
	 */
	public function setSetting($name, $value) {
		if (!$this->guid) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -303,10 +303,7 @@
 			$return = array();
 
 			foreach ($private_settings as $setting) {
-				$name = substr($setting->name, $ps_prefix_len);
-				$value = $setting->value;
-
-				$return[$name] = $value;
+				$return[$setting->name] = $setting->value;
 			}
 
 			return $return;
```
