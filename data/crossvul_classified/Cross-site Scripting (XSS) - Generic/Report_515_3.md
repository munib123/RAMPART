# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 515_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `515_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1116-1157 of the vulnerable file.

					}

					$updown = db_fetch_row_prepared("SELECT SUM(up_hosts) AS up, SUM(snmp_hosts) AS snmp
						FROM automation_processes
						WHERE network_id = ?", array($network['id']));

					if (empty($updown['up'])) {
						$updown['up']   = 0;
						$updown['snmp'] = 0;
					}
				} else {
					$updown['up']   = $network['up_hosts'];
					$updown['snmp'] = $network['snmp_hosts'];

					$mystat   = "<span class='idle'>" . __('Idle') . "</span>";
					$progress = "0/0/0";
				}
			}

			form_alternate_row('line' . $network['id'], true);
			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('automation_networks.php?action=edit&id=' . $network['id']) . '">' . $network['name'] . '</a>', $network['id']);
			form_selectable_cell($network['data_collector'], $network['id']);
			form_selectable_cell($sched_types[$network['sched_type']], $network['id']);
			form_selectable_cell(number_format_i18n($network['total_ips']), $network['id'], '', 'text-align:right;');
			form_selectable_cell($mystat, $network['id'], '', 'text-align:right;');
			form_selectable_cell($progress, $network['id'], '', 'text-align:right;');
			form_selectable_cell(number_format_i18n($updown['up']) . '/' . number_format_i18n($updown['snmp']), $network['id'], '', 'text-align:right;');
			form_selectable_cell(number_format_i18n($network['threads']), $network['id'], '', 'text-align:right;');
			form_selectable_cell(round($network['last_runtime'],2), $network['id'], '', 'text-align:right;');
			form_selectable_cell($network['enabled'] == '' || $network['sched_type'] == '1' ? __('N/A'):($network['next_start'] == '0000-00-00 00:00:00' ? substr($network['start_at'],0,16):substr($network['next_start'],0,16)), $network['id'], '', 'text-align:right;');
			form_selectable_cell($network['last_started'] == '0000-00-00 00:00:00' ? 'Never':substr($network['last_started'],0,16), $network['id'], '', 'text-align:right;');
			form_checkbox_cell($network['name'], $network['id']);
			form_end_row();
		}
	} else {
		print "<tr><td colspan='10'><em>" . __('No Networks Found') . "</em></td></tr>";
	}
	html_end_box(false);

	if (cacti_sizeof($networks)) {
		/* put the nav bar on the bottom as well */
		print $nav;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1133,17 +1133,17 @@
 			}
 
 			form_alternate_row('line' . $network['id'], true);
-			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('automation_networks.php?action=edit&id=' . $network['id']) . '">' . $network['name'] . '</a>', $network['id']);
-			form_selectable_cell($network['data_collector'], $network['id']);
+			form_selectable_cell('<a class="linkEditMain" href="' . html_escape('automation_networks.php?action=edit&id=' . $network['id']) . '">' . html_escape($network['name']) . '</a>', $network['id']);
+			form_selectable_ecell($network['data_collector'], $network['id']);
 			form_selectable_cell($sched_types[$network['sched_type']], $network['id']);
-			form_selectable_cell(number_format_i18n($network['total_ips']), $network['id'], '', 'text-align:right;');
-			form_selectable_cell($mystat, $network['id'], '', 'text-align:right;');
-			form_selectable_cell($progress, $network['id'], '', 'text-align:right;');
-			form_selectable_cell(number_format_i18n($updown['up']) . '/' . number_format_i18n($updown['snmp']), $network['id'], '', 'text-align:right;');
-			form_selectable_cell(number_format_i18n($network['threads']), $network['id'], '', 'text-align:right;');
-			form_selectable_cell(round($network['last_runtime'],2), $network['id'], '', 'text-align:right;');
-			form_selectable_cell($network['enabled'] == '' || $network['sched_type'] == '1' ? __('N/A'):($network['next_start'] == '0000-00-00 00:00:00' ? substr($network['start_at'],0,16):substr($network['next_start'],0,16)), $network['id'], '', 'text-align:right;');
-			form_selectable_cell($network['last_started'] == '0000-00-00 00:00:00' ? 'Never':substr($network['last_started'],0,16), $network['id'], '', 'text-align:right;');
+			form_selectable_cell(number_format_i18n($network['total_ips']), $network['id'], '', 'right');
+			form_selectable_cell($mystat, $network['id'], '', 'right');
+			form_selectable_cell($progress, $network['id'], '', 'right');
+			form_selectable_cell(number_format_i18n($updown['up']) . '/' . number_format_i18n($updown['snmp']), $network['id'], '', 'right');
+			form_selectable_cell(number_format_i18n($network['threads']), $network['id'], '', 'right');
+			form_selectable_cell(round($network['last_runtime'],2), $network['id'], '', 'right');
+			form_selectable_cell($network['enabled'] == '' || $network['sched_type'] == '1' ? __('N/A'):($network['next_start'] == '0000-00-00 00:00:00' ? substr($network['start_at'],0,16):substr($network['next_start'],0,16)), $network['id'], '', 'right');
+			form_selectable_cell($network['last_started'] == '0000-00-00 00:00:00' ? __('Never'):substr($network['last_started'],0,16), $network['id'], '', 'right');
 			form_checkbox_cell($network['name'], $network['id']);
 			form_end_row();
 		}
```
