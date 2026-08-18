# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 905-947 of the vulnerable file.

	$display_text = array(
		'name'         => array('display' => __('Data Input Name'),    'align' => 'left', 'sort' => 'ASC', 'tip' => __('The name of this Data Input Method.')),
		'nosort'       => array('display' => __('Deletable'),          'align' => 'right', 'tip' => __('Data Inputs that are in use cannot be Deleted. In use is defined as being referenced either by a Data Source or a Data Template.')),
		'data_sources' => array('display' => __('Data Sources Using'), 'align' => 'right', 'sort' => 'DESC', 'tip' => __('The number of Data Sources that use this Data Input Method.')),
		'templates'    => array('display' => __('Templates Using'),    'align' => 'right', 'sort' => 'DESC', 'tip' => __('The number of Data Templates that use this Data Input Method.')),
		'type_id'      => array('display' => __('Data Input Method'),  'align' => 'left', 'sort' => 'ASC', 'tip' => __('The method used to gather information for this Data Input Method.')));

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	$i = 0;
	if (cacti_sizeof($data_inputs)) {
		foreach ($data_inputs as $data_input) {
			/* hide system types */
			if ($data_input['templates'] > 0 || $data_input['data_sources'] > 0) {
				$disabled = true;
			} else {
				$disabled = false;
			}
			form_alternate_row('line' . $data_input['id'], true, $disabled);
			form_selectable_cell(filter_value($data_input['name'], get_request_var('filter'), 'data_input.php?action=edit&id=' . $data_input['id']), $data_input['id']);
			form_selectable_cell($disabled ? __('No'): __('Yes'), $data_input['id'],'', 'text-align:right');
			form_selectable_cell(number_format_i18n($data_input['data_sources'], '-1'), $data_input['id'],'', 'text-align:right');
			form_selectable_cell(number_format_i18n($data_input['templates'], '-1'), $data_input['id'],'', 'text-align:right');
			form_selectable_cell($input_types[$data_input['type_id']], $data_input['id']);
			form_checkbox_cell($data_input['name'], $data_input['id'], $disabled);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="' . (cacti_sizeof($display_text)+1) . '"><em>' . __('No Data Input Methods Found') . '</em></td></tr>';
	}

	html_end_box(false);

	if (cacti_sizeof($data_inputs)) {
		print $nav;
	}

	/* draw the dropdown containing a list of available actions for this form */
	draw_actions_dropdown($di_actions);

	form_end();
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -922,9 +922,9 @@
 			}
 			form_alternate_row('line' . $data_input['id'], true, $disabled);
 			form_selectable_cell(filter_value($data_input['name'], get_request_var('filter'), 'data_input.php?action=edit&id=' . $data_input['id']), $data_input['id']);
-			form_selectable_cell($disabled ? __('No'): __('Yes'), $data_input['id'],'', 'text-align:right');
-			form_selectable_cell(number_format_i18n($data_input['data_sources'], '-1'), $data_input['id'],'', 'text-align:right');
-			form_selectable_cell(number_format_i18n($data_input['templates'], '-1'), $data_input['id'],'', 'text-align:right');
+			form_selectable_cell($disabled ? __('No'):__('Yes'), $data_input['id'],'', 'right');
+			form_selectable_cell(number_format_i18n($data_input['data_sources'], '-1'), $data_input['id'],'', 'right');
+			form_selectable_cell(number_format_i18n($data_input['templates'], '-1'), $data_input['id'],'', 'right');
 			form_selectable_cell($input_types[$data_input['type_id']], $data_input['id']);
 			form_checkbox_cell($data_input['name'], $data_input['id'], $disabled);
 			form_end_row();
```
