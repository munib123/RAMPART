# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4297_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4297_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 964-1004 of the vulnerable file.


	$save['id']     = (empty($_data_query_id) ? '0' : $_data_query_id);
	$save['hash']   = $hash;

	foreach ($fields_data_query_edit as $field_name => $field_array) {
		/* make sure this field exists in the xml array first */
		if (isset($xml_array[$field_name])) {
			/* is the value of this field a hash or not? */
			if (preg_match('/hash_([a-f0-9]{2})([a-f0-9]{4})([a-f0-9]{32})/', $xml_array[$field_name])) {
				$save[$field_name] = resolve_hash_to_id($xml_array[$field_name], $hash_cache);
			} else {
				$save[$field_name] = xml_character_decode($xml_array[$field_name]);
			}
		}
	}

	if (isset($save['xml_path'])) {
		$path = str_replace('<path_cacti>', $config['base_path'], $save['xml_path']);

		if (!file_exists($path) || !is_readable($path)) {
			raise_message('resource_missing_' . $counter, __('Resource File: \'%s\' is missing or not readable.  Make sure you install it before using Data Query: \'%s\'', $path, $save['name']), MESSAGE_LEVEL_ERROR);
			$counter++;
		}
	}

	/* check for status changes */
	$status += compare_data($save, $previous_data, 'snmp_query');

	if (!$preview_only) {
		$data_query_id = sql_save($save, 'snmp_query');

		$hash_cache['data_query'][$hash] = $data_query_id;

		update_replication_crc(0, 'poller_replicate_snmp_query_crc');
	} else {
		$data_query_id = $_data_query_id;

		$hash_cache['data_query'][$hash] = $_data_query_id;
	}

	/* import into: snmp_query_graph */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -981,7 +981,7 @@
 		$path = str_replace('<path_cacti>', $config['base_path'], $save['xml_path']);
 
 		if (!file_exists($path) || !is_readable($path)) {
-			raise_message('resource_missing_' . $counter, __('Resource File: \'%s\' is missing or not readable.  Make sure you install it before using Data Query: \'%s\'', $path, $save['name']), MESSAGE_LEVEL_ERROR);
+			raise_message('resource_missing_' . $counter, __esc('Resource File: \'%s\' is missing or not readable.  Make sure you install it before using Data Query: \'%s\'', $path, $save['name']), MESSAGE_LEVEL_ERROR);
 			$counter++;
 		}
 	}
@@ -2090,7 +2090,7 @@
 
 			print "<ul>";
 			foreach($filestatus as $filename => $status) {
-				print "<li>" . ($preview ? __("[preview] "):"") . $filename . " [" . $status . "]</li>\n";
+				print "<li>" . ($preview ? __("[preview] "):"") . html_escape($filename) . " [" . $status . "]</li>\n";
 			}
 			print "</ul>";
 		} else {
```
