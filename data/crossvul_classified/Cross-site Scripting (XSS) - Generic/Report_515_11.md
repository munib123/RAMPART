# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_11
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_11`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1543-1583 of the vulnerable file.

			}

			/* keep copy of data source for comparison */
			$data_source_orig = $data_source;
			$data_source = api_plugin_hook_function('data_sources_table', $data_source);

			/* we're escaping strings here, so no need to escape them on form_selectable_cell */
			if (empty($data_source['data_template_name'])) {
				$data_template_name = '<em>' . __('None') . '</em>';
			} elseif ($data_source_orig['data_template_name'] != $data_source['data_template_name']) {
				/* was changed by plugin, plugin has to take care for html-escaping */
				$data_template_name = $data_source['data_template_name'];
			} elseif (get_request_var('rfilter') != '') {
				$data_template_name = filter_value($data_source['data_template_name'], get_request_var('rfilter'));
			} else {
				$data_template_name = html_escape($data_source['data_template_name']);
			}

			form_alternate_row('line' . $data_source['local_data_id'], true, $disabled);
			form_selectable_cell(filter_value(title_trim($data_source['name_cache'], read_config_option('max_title_length')), get_request_var('rfilter'), 'data_sources.php?action=ds_edit&id=' . $data_source['local_data_id']), $data_source['local_data_id']);
			form_selectable_cell($data_source['local_data_id'], $data_source['local_data_id'], '', 'text-align:right');
			form_selectable_cell(get_poller_interval($data_source['rrd_step'], $data_source['data_source_profile_id']), $data_source['local_data_id']);
			form_selectable_cell(api_data_source_deletable($data_source['local_data_id']) ? __('Yes') : __('No'), $data_source['local_data_id']);
			form_selectable_cell(($data_source['active'] == 'on' ? __('Yes') : __('No')), $data_source['local_data_id']);
			form_selectable_cell($data_template_name, $data_source['local_data_id']);
			form_checkbox_cell($data_source['name_cache'], $data_source['local_data_id'], $disabled);
			form_end_row();
		}
	} else {
		print "<tr class='tableRow'><td colspan='7'><em>" . __('No Data Sources Found') . "</em></td></tr>";
	}

	html_end_box(false);

	if (cacti_sizeof($data_sources)) {
		print $nav;
	}

	/* draw the dropdown containing a list of available actions for this form */
	draw_actions_dropdown($ds_actions);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1560,10 +1560,10 @@
 
 			form_alternate_row('line' . $data_source['local_data_id'], true, $disabled);
 			form_selectable_cell(filter_value(title_trim($data_source['name_cache'], read_config_option('max_title_length')), get_request_var('rfilter'), 'data_sources.php?action=ds_edit&id=' . $data_source['local_data_id']), $data_source['local_data_id']);
-			form_selectable_cell($data_source['local_data_id'], $data_source['local_data_id'], '', 'text-align:right');
+			form_selectable_cell($data_source['local_data_id'], $data_source['local_data_id'], '', 'right');
 			form_selectable_cell(get_poller_interval($data_source['rrd_step'], $data_source['data_source_profile_id']), $data_source['local_data_id']);
 			form_selectable_cell(api_data_source_deletable($data_source['local_data_id']) ? __('Yes') : __('No'), $data_source['local_data_id']);
-			form_selectable_cell(($data_source['active'] == 'on' ? __('Yes') : __('No')), $data_source['local_data_id']);
+			form_selectable_cell(($data_source['active'] == 'on' ? __('Yes'):__('No')), $data_source['local_data_id']);
 			form_selectable_cell($data_template_name, $data_source['local_data_id']);
 			form_checkbox_cell($data_source['name_cache'], $data_source['local_data_id'], $disabled);
 			form_end_row();
```
