# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1182-1222 of the vulnerable file.

	$nav = html_nav_bar('aggregate_graphs.php?action=edit&tab=items&id=' . get_request_var('id'), MAX_DISPLAY_PAGES, get_request_var('page'), $rows, $total_rows, 5, __('Graphs'), 'page', 'main');

	print $nav;

	$display_text = array(
		'title_cache'    => array('display' => __('Graph Title'), 'align' => 'left', 'sort' => 'ASC'),
		'local_graph_id' => array('display' => __('ID'), 'align' => 'right', 'sort' => 'ASC'),
		'agg_graph_id'   => array('display' => __('Included in Aggregate'), 'align' => 'left', 'sort' => 'ASC'),
		'height'         => array('display' => __('Size'), 'align' => 'right', 'sort' => 'ASC'));

	html_header_sort_checkbox($display_text, get_request_var('sort_column'), get_request_var('sort_direction'), false, 'aggregate_graphs.php?action=edit&id=' . get_request_var('id'));

	if (cacti_sizeof($graph_list) > 0) {
		foreach ($graph_list as $graph) {
			/* we're escaping strings here, so no need to escape them on form_selectable_cell */
			form_alternate_row('line' . $graph['local_graph_id'], true);

			if (validate_is_regex(get_request_var('rfilter'))) {
				form_selectable_cell(filter_value($graph['title_cache'], get_request_var('rfilter')), $graph['local_graph_id']);
			} else {
				form_selectable_cell(get_request_var('rfilter') != '' ? aggregate_format_text(html_escape($graph['title_cache']), get_request_var('rfilter')) : html_escape($graph['title_cache']), $graph['local_graph_id']);
			}

			form_selectable_cell($graph['local_graph_id'], $graph['local_graph_id'], '', 'right');
			form_selectable_cell(($graph['agg_graph_id'] != '' ? "<span class='associated'>" . __('Yes') . '</span>':"<span class='notAssociated'>" . __('No') . "</span>"), $graph['local_graph_id']);
			form_selectable_cell($graph['height'] . 'x' . $graph['width'], $graph['local_graph_id'], '', 'right');
			form_checkbox_cell($graph['title_cache'], $graph['local_graph_id']);
			form_end_row();
		}
	} else {
		print '<tr><td><em>' . __('No Graphs Found') . '</em></td></tr>';
	}

	html_end_box(false);

	/* put the nav bar on the bottom as well */
	print $nav;

	/* add a list of tree names to the actions dropdown */
	add_tree_names_to_actions_array();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1199,12 +1199,12 @@
 			if (validate_is_regex(get_request_var('rfilter'))) {
 				form_selectable_cell(filter_value($graph['title_cache'], get_request_var('rfilter')), $graph['local_graph_id']);
 			} else {
-				form_selectable_cell(get_request_var('rfilter') != '' ? aggregate_format_text(html_escape($graph['title_cache']), get_request_var('rfilter')) : html_escape($graph['title_cache']), $graph['local_graph_id']);
+				form_selectable_ecell(get_request_var('rfilter') != '' ? aggregate_format_text($graph['title_cache'], get_request_var('rfilter')) : $graph['title_cache'], $graph['local_graph_id']);
 			}
 
 			form_selectable_cell($graph['local_graph_id'], $graph['local_graph_id'], '', 'right');
 			form_selectable_cell(($graph['agg_graph_id'] != '' ? "<span class='associated'>" . __('Yes') . '</span>':"<span class='notAssociated'>" . __('No') . "</span>"), $graph['local_graph_id']);
-			form_selectable_cell($graph['height'] . 'x' . $graph['width'], $graph['local_graph_id'], '', 'right');
+			form_selectable_ecell($graph['height'] . 'x' . $graph['width'], $graph['local_graph_id'], '', 'right');
 			form_checkbox_cell($graph['title_cache'], $graph['local_graph_id']);
 			form_end_row();
 		}
@@ -1528,7 +1528,7 @@
 			form_selectable_cell(filter_value(title_trim($graph['title_cache'], read_config_option('max_title_length')), get_request_var('filter'), 'aggregate_graphs.php?action=edit&id=' . $graph['local_graph_id']), $graph['local_graph_id']);
 			form_selectable_cell($graph['local_graph_id'], $graph['local_graph_id'], '', 'right');
 			form_selectable_cell((empty($graph['name']) ? '<em>' . __('None') . '</em>' : filter_value($template_name, get_request_var('filter'))), $graph['local_graph_id']);
-			form_selectable_cell($graph['height'] . 'x' . $graph['width'], $graph['local_graph_id'], '', 'right');
+			form_selectable_ecell($graph['height'] . 'x' . $graph['width'], $graph['local_graph_id'], '', 'right');
 			form_checkbox_cell($graph['title_cache'], $graph['local_graph_id']);
 			form_end_row();
 		}
```
