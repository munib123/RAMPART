# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2653_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2653_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.

 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

include('./include/auth.php');

$debug = false;

if (isset_request_var('method')) {
	switch(get_nfilter_request_var('method')) {
		case 'stddev':
		case 'float':
		case 'variance':
		case 'fill':
			break;
		default:
			echo __("FATAL: Spike Kill method '%s' is Invalid\n", get_nfilter_request_var('method'));
			exit(1);
			break;
	}
}

if (is_realm_allowed(1043)) {
	$local_data_ids = db_fetch_assoc_prepared('SELECT DISTINCT data_template_rrd.local_data_id
		FROM graph_templates_item
		LEFT JOIN data_template_rrd
		ON graph_templates_item.task_item_id=data_template_rrd.id
		WHERE graph_templates_item.local_graph_id = ?', array(get_filter_request_var('local_graph_id')));

	$results = '';
	if (sizeof($local_data_ids)) {
		foreach($local_data_ids as $local_data_id) {
			$data_source_path = get_data_source_path($local_data_id['local_data_id'], true);

			if ($data_source_path != '') {
				if ($debug) {
					cacti_log(read_config_option('path_php_binary') . ' -q ' . $config['base_path'] . '/cli/removespikes.php ' .
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,7 @@
 		case 'fill':
 			break;
 		default:
-			echo __("FATAL: Spike Kill method '%s' is Invalid\n", get_nfilter_request_var('method'));
+			echo __("FATAL: Spike Kill method '%s' is Invalid\n", htmlspecialchars(get_nfilter_request_var('method'), ENT_QUOTES, 'UTF-8'));
 			exit(1);
 			break;
 	}
@@ -45,7 +45,8 @@
 		FROM graph_templates_item
 		LEFT JOIN data_template_rrd
 		ON graph_templates_item.task_item_id=data_template_rrd.id
-		WHERE graph_templates_item.local_graph_id = ?', array(get_filter_request_var('local_graph_id')));
+		WHERE graph_templates_item.local_graph_id = ?',
+		array(get_filter_request_var('local_graph_id')));
 
 	$results = '';
 	if (sizeof($local_data_ids)) {
```
