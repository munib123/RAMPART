# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 242-283 of the vulnerable file.


	html_header_checkbox(array(__('ID'), __('User'), __('Started'), __('Data Source'), __('Status'), __('Writable'), __('Exists'), __('Active'), __('RRD Match'), __('Valid Data'), __('RRD Updated'), __('Issue')));

	if (cacti_sizeof($checks)) {
		foreach ($checks as $check) {
			$info = unserialize($check['info']);
			$issues = explode("\n", $check['issue']);
			$issue_line = '';
			if (cacti_sizeof($issues)) {
				$issue_line = $issues[0];
			}
			$issue_title = implode($issues, '<br/>');

			$user = db_fetch_cell_prepared('SELECT username FROM user_auth WHERE id = ?', array($check['user']), 'username');
			form_alternate_row('line' . $check['id']);
			$name = get_data_source_title($check['datasource']);
			$title = $name;
			if (strlen($name) > 50) {
				$name = substr($name, 0, 50);
			}
			form_selectable_cell('<a class="linkEditMain" title="' . $title .'" href="' . htmlspecialchars('data_debug.php?action=view&id=' . $check['id']) . '">' . $name . '</a>', $check['id']);
			form_selectable_cell($user, $check['id']);
			form_selectable_cell(date('F j, Y, G:i', $check['started']), $check['id']);
			form_selectable_cell($check['datasource'], $check['id']);
			form_selectable_cell(debug_icon(($check['done'] ? (strlen($issue_line) ? 'off' : 'on' ) : '')), $check['id'], '', 'text-align: center;');
			form_selectable_cell(debug_icon($info['rrd_writable']), $check['id'], '', 'text-align: center;');
			form_selectable_cell(debug_icon($info['rrd_exists']), $check['id'], '', 'text-align: center;');
			form_selectable_cell(debug_icon($info['active']), $check['id'], '', 'text-align: center;');
			form_selectable_cell(debug_icon($info['rrd_match']), $check['id'], '', 'text-align: center;');
			form_selectable_cell(debug_icon($info['valid_data']), $check['id'], '', 'text-align: center;');
			form_selectable_cell(debug_icon(($info['rra_timestamp2'] != '' ? 1 : '')), $check['id'], '', 'text-align: center;');
			form_selectable_cell('<a class=\'linkEditMain\' href=\'#\' title="' . html_escape($issue_title) . '">' . html_escape(strlen(trim($issue_line)) ? $issue_line : '<none>') . '</a>', $check['id']);
			form_checkbox_cell($check['id'], $check['id']);
			form_end_row();
		}
	}else{
		print "<tr><td colspan='5'><em>" . __('No Checks') . "</em></td></tr>\n";
	}

	html_end_box(false);

	form_hidden_box('save_list', '1', '');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -259,18 +259,18 @@
 			if (strlen($name) > 50) {
 				$name = substr($name, 0, 50);
 			}
-			form_selectable_cell('<a class="linkEditMain" title="' . $title .'" href="' . htmlspecialchars('data_debug.php?action=view&id=' . $check['id']) . '">' . $name . '</a>', $check['id']);
-			form_selectable_cell($user, $check['id']);
+			form_selectable_cell('<a class="linkEditMain" title="' . $title .'" href="' . html_escape('data_debug.php?action=view&id=' . $check['id']) . '">' . html_escape($name) . '</a>', $check['id']);
+			form_selectable_ecell($user, $check['id']);
 			form_selectable_cell(date('F j, Y, G:i', $check['started']), $check['id']);
-			form_selectable_cell($check['datasource'], $check['id']);
-			form_selectable_cell(debug_icon(($check['done'] ? (strlen($issue_line) ? 'off' : 'on' ) : '')), $check['id'], '', 'text-align: center;');
-			form_selectable_cell(debug_icon($info['rrd_writable']), $check['id'], '', 'text-align: center;');
-			form_selectable_cell(debug_icon($info['rrd_exists']), $check['id'], '', 'text-align: center;');
-			form_selectable_cell(debug_icon($info['active']), $check['id'], '', 'text-align: center;');
-			form_selectable_cell(debug_icon($info['rrd_match']), $check['id'], '', 'text-align: center;');
-			form_selectable_cell(debug_icon($info['valid_data']), $check['id'], '', 'text-align: center;');
-			form_selectable_cell(debug_icon(($info['rra_timestamp2'] != '' ? 1 : '')), $check['id'], '', 'text-align: center;');
-			form_selectable_cell('<a class=\'linkEditMain\' href=\'#\' title="' . html_escape($issue_title) . '">' . html_escape(strlen(trim($issue_line)) ? $issue_line : '<none>') . '</a>', $check['id']);
+			form_selectable_ecell($check['datasource'], $check['id']);
+			form_selectable_cell(debug_icon(($check['done'] ? (strlen($issue_line) ? 'off' : 'on' ) : '')), $check['id'], '', 'center');
+			form_selectable_cell(debug_icon($info['rrd_writable']), $check['id'], '', 'center');
+			form_selectable_cell(debug_icon($info['rrd_exists']), $check['id'], '', 'center');
+			form_selectable_cell(debug_icon($info['active']), $check['id'], '', 'center');
+			form_selectable_cell(debug_icon($info['rrd_match']), $check['id'], '', 'center');
+			form_selectable_cell(debug_icon($info['valid_data']), $check['id'], '', 'center');
+			form_selectable_cell(debug_icon(($info['rra_timestamp2'] != '' ? 1 : '')), $check['id'], '', 'center');
+			form_selectable_cell('<a class=\'linkEditMain\' href=\'#\' title="' . html_escape($issue_title) . '">' . html_escape(strlen(trim($issue_line)) ? $issue_line : __('<none>')) . '</a>', $check['id']);
 			form_checkbox_cell($check['id'], $check['id']);
 			form_end_row();
 		}
@@ -345,9 +345,9 @@
 		$field_name = $field['name'];
 
 		form_alternate_row('line' . $i);
-		form_selectable_cell($field['title'], $i);
-
-		$value = '<not set>';
+		form_selectable_ecell($field['title'], $i);
+
+		$value = __('<not set>');
 		$icon  = '';
 
 		if (array_key_exists($field_name, $check['info'])) {
@@ -368,7 +368,7 @@
 			$value = substr($value, 0, 100);
 		}
 
-		form_selectable_cell($value, $i, '', '', $value_title);
+		form_selectable_ecell($value, $i, '', '', $value_title);
 		form_selectable_cell($icon, $i);
 
 		form_end_row();
@@ -377,15 +377,6 @@
 
 
 	html_end_box(false);
-
-/*
-	print "<pre>";
-	if (isset($check) && is_array($check)) {
-		print_r($check);
-	}
-	print "</pre>";
-*/
-
 }
 
 function debug_icon($result) {
```
