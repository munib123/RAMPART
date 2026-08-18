# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 641-682 of the vulnerable file.


	$display_text = array(
		'pgt.name'            => array('display' => __('Template Title'), 'align' => 'left', 'sort' => 'ASC'),
		'nosort'              => array('display' => __('Deletable'), 'align' => 'right', 'tip' => __('Aggregate Templates that are in use can not be Deleted.  In use is defined as being referenced by an Aggregate.')),
		'graphs.graphs'       => array('display' => __('Graphs Using'), 'align' => 'right', 'sort' => 'DESC'),
		'graph_template_name' => array('display' => __('Graph Template'), 'align' => 'left', 'sort' => 'ASC')
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	if (cacti_sizeof($template_list)) {
		foreach ($template_list as $template) {
			if ($template['graphs'] > 0) {
				$disabled = true;
			} else {
				$disabled = false;
			}

			form_alternate_row('line' . $template['id'], true, $disabled);
			form_selectable_cell(filter_value($template['name'], get_request_var('filter'), 'aggregate_templates.php?action=edit&id=' . $template['id'] . '&page=1'), $template['id']);
			form_selectable_cell($disabled ? 'No':'Yes', $template['id'], '', 'text-align:right');
			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('aggregate_graphs.php?reset=true&template_id=' . $template['id']) . '">' . number_format_i18n($template['graphs'], '-1') . '</a>', $template['id'], '', 'text-align:right;');
			form_selectable_cell(filter_value($template['graph_template_name'], get_request_var('filter')), $template['id']);
			form_checkbox_cell($template['graph_template_name'], $template['id'], $disabled);
			form_end_row();
		}
	} else {
		print "<tr><td colspan='" . (cacti_sizeof($display_text)+1) . "'><em>" . __('No Aggregate Templates Found') . "</em></td></tr>\n";
	}

	html_end_box(false);

	if (cacti_sizeof($template_list)) {
		/* put the nav bar on the bottom as well */
		print $nav;
	}

	/* draw the dropdown containing a list of available actions for this form */
	draw_actions_dropdown($aggregate_actions);

	form_end();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -658,8 +658,8 @@
 
 			form_alternate_row('line' . $template['id'], true, $disabled);
 			form_selectable_cell(filter_value($template['name'], get_request_var('filter'), 'aggregate_templates.php?action=edit&id=' . $template['id'] . '&page=1'), $template['id']);
-			form_selectable_cell($disabled ? 'No':'Yes', $template['id'], '', 'text-align:right');
-			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('aggregate_graphs.php?reset=true&template_id=' . $template['id']) . '">' . number_format_i18n($template['graphs'], '-1') . '</a>', $template['id'], '', 'text-align:right;');
+			form_selectable_cell($disabled ? __('No'):__('Yes'), $template['id'], '', 'right');
+			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('aggregate_graphs.php?reset=true&template_id=' . $template['id']) . '">' . number_format_i18n($template['graphs'], '-1') . '</a>', $template['id'], '', 'right');
 			form_selectable_cell(filter_value($template['graph_template_name'], get_request_var('filter')), $template['id']);
 			form_checkbox_cell($template['graph_template_name'], $template['id'], $disabled);
 			form_end_row();
```
