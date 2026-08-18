# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_10
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_10`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 984-1029 of the vulnerable file.

			if ($profile['data_sources']) {
				$readonly = true;
			} else {
				$readonly = false;
			}

			if ($profile['data_sources'] > 0) {
				$ds = '<a class="linkEditMain" href="' . $config['url_path'] . 'data_sources.php?reset=true&profile=' . $profile['id'] . '">' . number_format_i18n($profile['data_sources'], '-1') . '</a>';
			} else {
				$ds = number_format_i18n($profile['data_sources'], '-1');
			}

			if ($profile['templates'] > 0) {
				$dt = '<a class="linkEditMain" href="' . $config['url_path'] . 'data_templates.php?reset=true&profile=' . $profile['id'] . '">' . number_format_i18n($profile['templates'], '-1') . '</a>';
			} else {
				$dt = number_format_i18n($profile['templates'], '-1');
			}

			form_alternate_row('line' . $profile['id'], false, $disabled);
			form_selectable_cell(filter_value($profile['name'], get_request_var('filter'), 'data_source_profiles.php?action=edit&id=' . $profile['id']), $profile['id']);
			form_selectable_cell($profile['default'] == 'on' ? __('Yes'):'', $profile['id'], '', 'text-align:right');
			form_selectable_cell($disabled ? __('No') : __('Yes'), $profile['id'], '', 'text-align:right');
			form_selectable_cell($readonly ? __('Yes') : __('No'), $profile['id'], '', 'text-align:right');
			form_selectable_cell($sampling_intervals[$profile['step']], $profile['id'], '', 'text-align:right');
			form_selectable_cell($heartbeats[$profile['heartbeat']], $profile['id'], '', 'text-align:right');
			form_selectable_cell($ds, $profile['id'], '', 'text-align:right');
			form_selectable_cell($dt, $profile['id'], '', 'text-align:right');
			form_checkbox_cell($profile['name'], $profile['id'], $disabled);
			form_end_row();
		}
	} else {
		print "<tr class='tableRow'><td colspan='4'><em>" . __('No Data Source Profiles Found') . "</em></td></tr>\n";
	}

	html_end_box(false);

	if (cacti_sizeof($profile_list)) {
		print $nav;
	}

	/* draw the dropdown containing a list of available actions for this form */
	draw_actions_dropdown($profile_actions);

	form_end();
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1001,13 +1001,13 @@
 
 			form_alternate_row('line' . $profile['id'], false, $disabled);
 			form_selectable_cell(filter_value($profile['name'], get_request_var('filter'), 'data_source_profiles.php?action=edit&id=' . $profile['id']), $profile['id']);
-			form_selectable_cell($profile['default'] == 'on' ? __('Yes'):'', $profile['id'], '', 'text-align:right');
-			form_selectable_cell($disabled ? __('No') : __('Yes'), $profile['id'], '', 'text-align:right');
-			form_selectable_cell($readonly ? __('Yes') : __('No'), $profile['id'], '', 'text-align:right');
-			form_selectable_cell($sampling_intervals[$profile['step']], $profile['id'], '', 'text-align:right');
-			form_selectable_cell($heartbeats[$profile['heartbeat']], $profile['id'], '', 'text-align:right');
-			form_selectable_cell($ds, $profile['id'], '', 'text-align:right');
-			form_selectable_cell($dt, $profile['id'], '', 'text-align:right');
+			form_selectable_cell($profile['default'] == 'on' ? __('Yes'):'', $profile['id'], '', 'right');
+			form_selectable_cell($disabled ? __('No'):__('Yes'), $profile['id'], '', 'right');
+			form_selectable_cell($readonly ? __('Yes'):__('No'), $profile['id'], '', 'right');
+			form_selectable_cell($sampling_intervals[$profile['step']], $profile['id'], '', 'right');
+			form_selectable_cell($heartbeats[$profile['heartbeat']], $profile['id'], '', 'right');
+			form_selectable_cell($ds, $profile['id'], '', 'right');
+			form_selectable_cell($dt, $profile['id'], '', 'right');
 			form_checkbox_cell($profile['name'], $profile['id'], $disabled);
 			form_end_row();
 		}
```
