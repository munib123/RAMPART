# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1362-1405 of the vulnerable file.

		'name'              => array('display' => __('Data Query Name'), 'align' => 'left', 'sort' => 'ASC', 'tip' => __('The name of this Data Query.')),
		'id'                => array('display' => __('ID'), 'align' => 'right', 'sort' => 'ASC', 'tip' => __('The internal ID for this Graph Template.  Useful when performing automation or debugging.')),
		'nosort'            => array('display' => __('Deletable'), 'align' => 'right', 'tip' => __('Data Queries that are in use cannot be Deleted. In use is defined as being referenced by either a Graph or a Graph Template.')),
		'graphs'            => array('display' => __('Graphs Using'), 'align' => 'right', 'sort' => 'DESC', 'tip' => __('The number of Graphs using this Data Query.')),
		'templates'         => array('display' => __('Templates Using'), 'align' => 'right', 'sort' => 'DESC', 'tip' => __('The number of Graphs Templates using this Data Query.')),
		'data_input_method' => array('display' => __('Data Input Method'), 'align' => 'left', 'sort' => 'ASC', 'tip' => __('The Data Input Method used to collect data for Data Sources associated with this Data Query.')));

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	$i = 0;
	if (cacti_sizeof($snmp_queries)) {
		foreach ($snmp_queries as $snmp_query) {
			if ($snmp_query['graphs'] == 0 && $snmp_query['templates'] == 0) {
				$disabled = false;
			} else {
				$disabled = true;
			}

			form_alternate_row('line' . $snmp_query['id'], true, $disabled);
			form_selectable_cell(filter_value($snmp_query['name'], get_request_var('filter'), 'data_queries.php?action=edit&id=' . $snmp_query['id']), $snmp_query['id']);
			form_selectable_cell($snmp_query['id'], $snmp_query['id'], '', 'text-align:right;');
			form_selectable_cell($disabled ? __('No') : __('Yes'), $snmp_query['id'], '', 'text-align:right');
			form_selectable_cell(number_format_i18n($snmp_query['graphs'], '-1'), $snmp_query['id'], '', 'text-align:right');
			form_selectable_cell(number_format_i18n($snmp_query['templates'], '-1'), $snmp_query['id'], '', 'text-align:right');
			form_selectable_cell(filter_value($snmp_query['data_input_method'], get_request_var('filter')), $snmp_query['id']);
			form_checkbox_cell($snmp_query['name'], $snmp_query['id'], $disabled);
			form_end_row();
		}
	} else {
		print "<tr class='tableRow'><td colspan='5'><em>" . __('No Data Queries Found') . "</em></td></tr>";
	}

	html_end_box(false);

	if (cacti_sizeof($snmp_queries)) {
		print $nav;
	}

	/* draw the dropdown containing a list of available actions for this form */
	draw_actions_dropdown($dq_actions);

	form_end();
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1379,10 +1379,10 @@
 
 			form_alternate_row('line' . $snmp_query['id'], true, $disabled);
 			form_selectable_cell(filter_value($snmp_query['name'], get_request_var('filter'), 'data_queries.php?action=edit&id=' . $snmp_query['id']), $snmp_query['id']);
-			form_selectable_cell($snmp_query['id'], $snmp_query['id'], '', 'text-align:right;');
-			form_selectable_cell($disabled ? __('No') : __('Yes'), $snmp_query['id'], '', 'text-align:right');
-			form_selectable_cell(number_format_i18n($snmp_query['graphs'], '-1'), $snmp_query['id'], '', 'text-align:right');
-			form_selectable_cell(number_format_i18n($snmp_query['templates'], '-1'), $snmp_query['id'], '', 'text-align:right');
+			form_selectable_cell($snmp_query['id'], $snmp_query['id'], '', 'right');
+			form_selectable_cell($disabled ? __('No'):__('Yes'), $snmp_query['id'], '', 'right');
+			form_selectable_cell(number_format_i18n($snmp_query['graphs'], '-1'), $snmp_query['id'], '', 'right');
+			form_selectable_cell(number_format_i18n($snmp_query['templates'], '-1'), $snmp_query['id'], '', 'right');
 			form_selectable_cell(filter_value($snmp_query['data_input_method'], get_request_var('filter')), $snmp_query['id']);
 			form_checkbox_cell($snmp_query['name'], $snmp_query['id'], $disabled);
 			form_end_row();
```
