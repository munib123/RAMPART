# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 930-970 of the vulnerable file.


	print $nav;

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'name'               => array('display' => __('Rule Name'),      'align' => 'left',  'sort' => 'ASC'),
		'id'                 => array('display' => __('ID'),             'align' => 'right', 'sort' => 'ASC'),
		'tree_name'          => array('display' => __('Hook into Tree'), 'align' => 'left',  'sort' => 'ASC'),
		'subtree_name'       => array('display' => __('At Subtree'),     'align' => 'left',  'sort' => 'ASC'),
		'leaf_type'          => array('display' => __('This Type'),      'align' => 'left',  'sort' => 'ASC'),
		'host_grouping_type' => array('display' => __('Using Grouping'), 'align' => 'left',  'sort' => 'ASC'),
		'enabled'            => array('display' => __('Enabled'),        'align' => 'right', 'sort' => 'ASC')
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false);

	if (cacti_sizeof($automation_tree_rules)) {
		foreach ($automation_tree_rules as 	$automation_tree_rule) {
			$tree_item_type_name = ((empty($automation_tree_rule['leaf_type'])) ? '<em>' . __('None') . '</em>' : $automation_tree_item_types[$automation_tree_rule['leaf_type']]);
			$subtree_name = ((empty($automation_tree_rule['subtree_name'])) ? '<em>' . __('ROOT') . '</em>' : $automation_tree_rule['subtree_name']);
			$tree_host_grouping_type = ((empty($host_group_types[$automation_tree_rule['host_grouping_type']])) ? '' : $host_group_types[$automation_tree_rule['host_grouping_type']]);
			form_alternate_row('line' .  $automation_tree_rule['id'], true);

			form_selectable_cell(filter_value($automation_tree_rule['name'], get_request_var('filter'), 'automation_tree_rules.php?action=edit&id=' . $automation_tree_rule['id'] . '&page=1'), $automation_tree_rule['id']);
			form_selectable_cell($automation_tree_rule['id'], $automation_tree_rule['id'], '', 'text-align:right');
			form_selectable_cell($automation_tree_rule['tree_name'], $automation_tree_rule['id']);
			form_selectable_cell($subtree_name, $automation_tree_rule['id']);
			form_selectable_cell($tree_item_type_name, $automation_tree_rule['id']);
			form_selectable_cell($tree_host_grouping_type, $automation_tree_rule['id']);
			form_selectable_cell($automation_tree_rule['enabled'] ? __('Enabled'):__('Disabled'), $automation_tree_rule['id'], '', 'text-align:right');
			form_checkbox_cell($automation_tree_rule['name'], $automation_tree_rule['id']);

			form_end_row();
		}
	} else {
		print "<tr><td colspan='9'><em>" . __('No Tree Rules Found') . "</em></td></tr>\n";
	}

	html_end_box(false);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -947,13 +947,13 @@
 	if (cacti_sizeof($automation_tree_rules)) {
 		foreach ($automation_tree_rules as 	$automation_tree_rule) {
 			$tree_item_type_name = ((empty($automation_tree_rule['leaf_type'])) ? '<em>' . __('None') . '</em>' : $automation_tree_item_types[$automation_tree_rule['leaf_type']]);
-			$subtree_name = ((empty($automation_tree_rule['subtree_name'])) ? '<em>' . __('ROOT') . '</em>' : $automation_tree_rule['subtree_name']);
+			$subtree_name = ((empty($automation_tree_rule['subtree_name'])) ? '<em>' . __('ROOT') . '</em>' : html_escape($automation_tree_rule['subtree_name']));
 			$tree_host_grouping_type = ((empty($host_group_types[$automation_tree_rule['host_grouping_type']])) ? '' : $host_group_types[$automation_tree_rule['host_grouping_type']]);
 			form_alternate_row('line' .  $automation_tree_rule['id'], true);
 
 			form_selectable_cell(filter_value($automation_tree_rule['name'], get_request_var('filter'), 'automation_tree_rules.php?action=edit&id=' . $automation_tree_rule['id'] . '&page=1'), $automation_tree_rule['id']);
 			form_selectable_cell($automation_tree_rule['id'], $automation_tree_rule['id'], '', 'text-align:right');
-			form_selectable_cell($automation_tree_rule['tree_name'], $automation_tree_rule['id']);
+			form_selectable_ecell($automation_tree_rule['tree_name'], $automation_tree_rule['id']);
 			form_selectable_cell($subtree_name, $automation_tree_rule['id']);
 			form_selectable_cell($tree_item_type_name, $automation_tree_rule['id']);
 			form_selectable_cell($tree_host_grouping_type, $automation_tree_rule['id']);
```
