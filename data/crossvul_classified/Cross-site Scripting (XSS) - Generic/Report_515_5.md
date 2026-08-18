# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 89-129 of the vulnerable file.

        cdef_item_dnd();

        break;
	default:
		top_header();

		cdef();

		bottom_footer();
		break;
}

/* --------------------------
    Global Form Functions
   -------------------------- */

function draw_cdef_preview($cdef_id) {
	?>
	<tr class='even'>
		<td style='padding:4px'>
			<pre>cdef=<?php print get_cdef($cdef_id, true);?></pre>
		</td>
	</tr>
	<?php
}


/* --------------------------
    The Save Function
   -------------------------- */

function form_save() {

	// make sure ids are numeric
	if (isset_request_var('id') && ! is_numeric(get_filter_request_var('id'))) {
		set_request_var('id', 0);
	}

	if (isset_request_var('cdef_id') && ! is_numeric(get_filter_request_var('cdef_id'))) {
		set_request_var('cdef_id', 0);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,7 +106,7 @@
 	?>
 	<tr class='even'>
 		<td style='padding:4px'>
-			<pre>cdef=<?php print get_cdef($cdef_id, true);?></pre>
+			<pre>cdef=<?php print html_escape(get_cdef($cdef_id, true));?></pre>
 		</td>
 	</tr>
 	<?php
@@ -433,7 +433,7 @@
 	draw_cdef_preview(get_request_var('cdef_id'));
 	html_end_box();
 
-	form_start('cdef.php', 'form_cdef');
+	form_start('cdef.php', 'chk');
 
 	$cdef_name = db_fetch_cell_prepared('SELECT name
 		FROM cdef
@@ -897,9 +897,9 @@
 
 			form_alternate_row('line' . $cdef['id'], false, $disabled);
 			form_selectable_cell(filter_value($cdef['name'], get_request_var('filter'), 'cdef.php?action=edit&id=' . $cdef['id']), $cdef['id']);
-			form_selectable_cell($disabled ? __('No') : __('Yes'), $cdef['id'], '', 'text-align:right');
-			form_selectable_cell(number_format_i18n($cdef['graphs'], '-1'), $cdef['id'], '', 'text-align:right');
-			form_selectable_cell(number_format_i18n($cdef['templates'], '-1'), $cdef['id'], '', 'text-align:right');
+			form_selectable_cell($disabled ? __('No'):__('Yes'), $cdef['id'], '', 'right');
+			form_selectable_cell(number_format_i18n($cdef['graphs'], '-1'), $cdef['id'], '', 'right');
+			form_selectable_cell(number_format_i18n($cdef['templates'], '-1'), $cdef['id'], '', 'right');
 			form_checkbox_cell($cdef['name'], $cdef['id'], $disabled);
 			form_end_row();
 		}
```
