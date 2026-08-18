# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 807_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `807_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 350-390 of the vulnerable file.

		//kill
		if (permission_exists('operator_panel_kill') || in_array($extension, $_SESSION['user']['extensions'])) {
			if ($ext['variable_bridge_uuid'] == '' && $ext_state == 'ringing') {
				$call_identifier_kill = $ext['uuid'];
			}
			else if ($dir_icon == 'outbound') {
				$call_identifier_kill = $ext['uuid'];
			}
			else {
				$call_identifier_kill = $call_identifier;
			}
			$block .= 			"<img src='resources/images/kill.png' style='width: 12px; height: 12px; border: none; margin: 4px 0px 0px 5px; cursor: pointer;' title='".$text['label-kill']."' onclick=\"kill_call('".$call_identifier_kill."');\" ".$onhover_pause_refresh.">";
		}
		$block .=				"</span>";
		//transfer
		if (in_array($extension, $_SESSION['user']['extensions']) && $ext_state == 'active') {
			$block .= 			"<img id='destination_control_".$extension."_transfer' class='destination_control' src='resources/images/keypad_transfer.png' style='width: 12px; height: 12px; border: none; margin: 4px 0px 0px 5px; cursor: pointer;' onclick=\"toggle_destination('".$extension."', 'transfer');\" ".$onhover_pause_refresh.">";
		}
		$block .= "			</td></tr></table>";
		if (permission_exists('operator_panel_call_details')) {
			$block .= "			<span id='op_caller_details_".$extension."'><strong>".$call_name."</strong><br>".$call_number."</span>";
		}
		$block .= "		</span>";
		//transfer
		if (in_array($extension, $_SESSION['user']['extensions']) && $ext_state == 'active') {
			$call_identifier_transfer = $ext['variable_bridge_uuid'];
			$block .= "		<form id='frm_destination_".$extension."_transfer' onsubmit=\"go_destination('".$extension."', document.getElementById('destination_".$extension."_transfer').value, 'transfer', '".$call_identifier_transfer."'); return false;\">";
			$block .= "			<input type='text' class='formfld' id='destination_".$extension."_transfer' style='width: 100px; min-width: 100px; max-width: 100px; margin-top: 3px; text-align: center; display: none;' onblur=\"toggle_destination('".$extension."', 'transfer');\">";
			$block .= "		</form>\n";
		}
	}
	else {
		//call
		if (in_array($extension, $_SESSION['user']['extensions'])) {
			$block .= "		<img id='destination_control_".$extension."_call' class='destination_control' src='resources/images/keypad_call.png' style='width: 12px; height: 12px; border: none; margin-top: 26px; margin-right: 1px; cursor: pointer;' align='right' onclick=\"toggle_destination('".$extension."', 'call');\" ".$onhover_pause_refresh.">";
			$block .= "		<form id='frm_destination_".$extension."_call' onsubmit=\"go_destination('".$extension."', document.getElementById('destination_".$extension."_call').value, 'call'); return false;\">";
			$block .= "			<input type='text' class='formfld' id='destination_".$extension."_call' style='width: 100px; min-width: 100px; max-width: 100px; margin-top: 10px; text-align: center; display: none;' onblur=\"toggle_destination('".$extension."', 'call');\">";
			$block .= "		</form>\n";
		}
	}
	$block .= "		</td>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -367,7 +367,7 @@
 		}
 		$block .= "			</td></tr></table>";
 		if (permission_exists('operator_panel_call_details')) {
-			$block .= "			<span id='op_caller_details_".$extension."'><strong>".$call_name."</strong><br>".$call_number."</span>";
+			$block .= "			<span id='op_caller_details_".$extension."'><strong>".escape($call_name)."</strong><br>".escape($call_number)."</span>";
 		}
 		$block .= "		</span>";
 		//transfer
```
