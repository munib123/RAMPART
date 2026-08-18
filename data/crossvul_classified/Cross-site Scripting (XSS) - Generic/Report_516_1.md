# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 516_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `516_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 832-872 of the vulnerable file.

				$disabled = true;
			} else {
				$disabled = false;
			}

			if ($poller['disabled'] == 'on') {
				$poller['status'] = 4;
			}else if ($poller['heartbeat'] > 310) {
				$poller['status'] = 6;
			}

			$mma = round($poller['avg_time'], 2) . '/' .  round($poller['max_time'], 2);

			if (empty($poller['name'])) {
				$poller['name'] = '&lt;no name&gt;';
			}

			form_alternate_row('line' . $poller['id'], true, $disabled);
			form_selectable_cell(filter_value($poller['name'], get_request_var('filter'), 'pollers.php?action=edit&id=' . $poller['id']), $poller['id']);
			form_selectable_cell($poller['id'], $poller['id'], '', 'right');
			form_selectable_cell($poller['hostname'], $poller['id'], '', 'right');
			form_selectable_cell($poller_status[$poller['status']], $poller['id'], '', 'center');
			form_selectable_cell($poller['processes'] . '/' . $poller['threads'], $poller['id'], '', 'right');
			form_selectable_cell(number_format_i18n($poller['total_time'], 2), $poller['id'], '', 'right');
			form_selectable_cell($mma, $poller['id'], '', 'right');
			form_selectable_cell(number_format_i18n($poller['hosts'], '-1'), $poller['id'], '', 'right');
			form_selectable_cell(number_format_i18n($poller['snmp'], '-1'), $poller['id'], '', 'right');
			form_selectable_cell(number_format_i18n($poller['script'], '-1'), $poller['id'], '', 'right');
			form_selectable_cell(number_format_i18n($poller['server'], '-1'), $poller['id'], '', 'right');
			form_selectable_cell(substr($poller['last_update'], 5), $poller['id'], '', 'right');
			form_selectable_cell(substr($poller['last_status'], 5), $poller['id'], '', 'right');

			if ($poller['id'] == 1) {
				form_selectable_cell(__('N/A'), $poller['id'], '', 'right');
			} else {
				form_selectable_cell(substr($poller['last_sync'], 5), $poller['id'], '', 'right');
			}

			form_checkbox_cell($poller['name'], $poller['id'], $disabled);
			form_end_row();
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -849,7 +849,7 @@
 			form_alternate_row('line' . $poller['id'], true, $disabled);
 			form_selectable_cell(filter_value($poller['name'], get_request_var('filter'), 'pollers.php?action=edit&id=' . $poller['id']), $poller['id']);
 			form_selectable_cell($poller['id'], $poller['id'], '', 'right');
-			form_selectable_cell($poller['hostname'], $poller['id'], '', 'right');
+			form_selectable_cell(html_escape($poller['hostname']), $poller['id'], '', 'right');
 			form_selectable_cell($poller_status[$poller['status']], $poller['id'], '', 'center');
 			form_selectable_cell($poller['processes'] . '/' . $poller['threads'], $poller['id'], '', 'right');
 			form_selectable_cell(number_format_i18n($poller['total_time'], 2), $poller['id'], '', 'right');
```
