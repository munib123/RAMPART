# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2591_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2591_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 130-170 of the vulnerable file.

	/* you cannot have per-user graph settings if cacti's user management is not turned on */
	if (read_config_option('auth_method') == 0) {
		raise_message(6);
		display_output_messages();
		return;
	}

	if (get_request_var('action') == 'edit') {
		if (isset($_SERVER['HTTP_REFERER'])) {
			$timespan_sel_pos = strpos($_SERVER['HTTP_REFERER'],'&predefined_timespan');
			if ($timespan_sel_pos) {
				$_SERVER['HTTP_REFERER'] = substr($_SERVER['HTTP_REFERER'],0,$timespan_sel_pos);
			}
		}

		$_SESSION['profile_referer'] = (isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER']:'graph_view.php');
	}

	form_start('auth_profile.php');

	html_start_box( __('User Account Details'), '100%', true, '3', 'center', '');

	$current_user = db_fetch_row_prepared('SELECT * FROM user_auth WHERE id = ?', array($_SESSION['sess_user_id']));

	if (!sizeof($current_user)) {
		return;
	}

	// Set the graph views the user has permission to
	unset($graph_views);
	if (is_view_allowed('show_tree')) {
		$graph_views[1] = __('Tree View');
	}

	if (is_view_allowed('show_list')) {
		$graph_views[2] = __('List View');
	}

	if (is_view_allowed('show_preview')) {
		$graph_views[2] = __('Preview View');
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,7 +147,7 @@
 
 	form_start('auth_profile.php');
 
-	html_start_box( __('User Account Details'), '100%', true, '3', 'center', '');
+	html_start_box(__('User Account Details'), '100%', true, '3', 'center', '');
 
 	$current_user = db_fetch_row_prepared('SELECT * FROM user_auth WHERE id = ?', array($_SESSION['sess_user_id']));
 
@@ -418,7 +418,7 @@
 		});
 
 		$('input[value="<?php print __esc('Return');?>"]').unbind().click(function(event) {
-			document.location = '<?php print $_SESSION['profile_referer'];?>';
+			document.location = '<?php print htmlspecialchars($_SESSION['profile_referer']);?>';
 		});
 	});
 
@@ -427,7 +427,7 @@
 
 	form_hidden_box('save_component_graph_config','1','');
 
-	form_save_buttons(array(array('id' => 'return', 'value' => 'Return'), array('id' => 'save', 'value' => 'Save')));
+	form_save_buttons(array(array('id' => 'return', 'value' => __esc('Return')), array('id' => 'save', 'value' => __esc('Save'))));
 
 	form_end();
 }
```
