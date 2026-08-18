# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 558-600 of the vulnerable file.

	$display_text = array(
		'name'      => array(__('Template Title'), 'ASC'),
		'nosort'    => array('display' => __('Deletable'), 'align' => 'right', 'tip' => __('Color Templates that are in use cannot be Deleted. In use is defined as being referenced by an Aggregate Template.')),
		'graphs'    => array('display' => __('Graphs'), 'align' => 'right', 'sort' => 'DESC'),
		'templates' => array('display' => __('Templates'), 'align' => 'right', 'sort' => 'DESC')
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	if (cacti_sizeof($template_list)) {
		foreach ($template_list as $template) {
			if ($template['templates'] > 0) {
				$disabled = true;
			} else {
				$disabled = false;
			}

			form_alternate_row('line' . $template['color_template_id'], true);

			form_selectable_cell(filter_value($template['name'], get_request_var('filter'), 'color_templates.php?action=template_edit&color_template_id=' . $template['color_template_id'] . '&page=1'), $template['color_template_id']);
			form_selectable_cell($disabled ? __('No') : __('Yes'), $template['color_template_id'], '', 'text-align:right');
            form_selectable_cell(number_format_i18n($template['graphs']), $template['color_template_id'], '', 'text-align:right;');
            form_selectable_cell(number_format_i18n($template['templates']), $template['color_template_id'], '', 'text-align:right;');
			form_checkbox_cell($template['name'], $template['color_template_id'], $disabled);
			form_end_row();
		}
	} else {
		print "<tr><td colspan='" . (cacti_sizeof($display_text)+1) . "'><em>" . __('No Color Templates Found') ."</em></td></tr>\n";
	}

	html_end_box(false);

	if (cacti_sizeof($template_list)) {
		print $nav;
	}

	/* draw the dropdown containing a list of available actions for this form */
	draw_actions_dropdown($aggregate_actions);

	form_end();

	?>
	<script type='text/javascript'>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -575,9 +575,9 @@
 			form_alternate_row('line' . $template['color_template_id'], true);
 
 			form_selectable_cell(filter_value($template['name'], get_request_var('filter'), 'color_templates.php?action=template_edit&color_template_id=' . $template['color_template_id'] . '&page=1'), $template['color_template_id']);
-			form_selectable_cell($disabled ? __('No') : __('Yes'), $template['color_template_id'], '', 'text-align:right');
-            form_selectable_cell(number_format_i18n($template['graphs']), $template['color_template_id'], '', 'text-align:right;');
-            form_selectable_cell(number_format_i18n($template['templates']), $template['color_template_id'], '', 'text-align:right;');
+			form_selectable_cell($disabled ? __('No'):__('Yes'), $template['color_template_id'], '', 'right');
+			form_selectable_cell(number_format_i18n($template['graphs']), $template['color_template_id'], '', 'right');
+			form_selectable_cell(number_format_i18n($template['templates']), $template['color_template_id'], '', 'right');
 			form_checkbox_cell($template['name'], $template['color_template_id'], $disabled);
 			form_end_row();
 		}
```
