# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 173_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `173_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 227-267 of the vulnerable file.

		'1.0.6' => [
			'image_load_max_filesize_mb' => '3',
		],
		'1.0.7' => NULL,
		// 3.8.13
		'1.0.8' => [
			'upload_max_image_width' => '0',
			'upload_max_image_height'=> '0',
		],
		// 3.9.5
		'1.0.9' => [
			'auto_delete_guest_uploads' => NULL,
		],
		'1.0.10' => [
			'enable_user_content_delete' => 1,
			'enable_plugin_route' => 1,
			'sdk_pup_url' => NULL,
		],
		'1.0.11' => NULL,
		'1.0.12' => NULL,
	];
	// Settings that must be renamed from NAME to NEW NAME and DELETE old NAME
	$settings_rename = [];

	// Settings that must be renamed from NAME to NEW NAME and doesn't delete old NAME
	$settings_switch = [];

	$chv_initial_settings = [];
	foreach($settings_updates as $k => $v) {
		if(is_null($v)) continue;
		$chv_initial_settings += $v;
	}

	// Detect 2.X
	try {
		$is_2X = DB::get('info', ['key' => 'version']) ? true : false;
	} catch(Exception $e) {
		$is_2X = false;
	}

	/* Stats query from 3.7.0 up to 3.8.13 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -244,6 +244,7 @@
 		],
 		'1.0.11' => NULL,
 		'1.0.12' => NULL,
+		'1.0.13' => NULL,
 	];
 	// Settings that must be renamed from NAME to NEW NAME and DELETE old NAME
 	$settings_rename = [];
```
