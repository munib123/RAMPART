# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1156_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1156_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 97-137 of the vulnerable file.

	$status_options[5]['status'] = "Logged Out";
	$status_options[5]['label'] = $text['label-status_logged_out'];
	$status_options[5]['style'] = "op_btn_status_logged_out";

	if (is_array($status_options)) foreach ($status_options as $status_option) {
		echo "	<input type='button' id='".$status_option['style']."' class='btn' value=\"".$status_option['label']."\" onclick=\"send_cmd('index.php?status='+escape('".$status_option['status']."')); this.disabled='disabled'; refresh_start();\" ".$onhover_pause_refresh.">\n";
	}
}

echo "		</td>";
echo "		<td valign='top' align='right' width='50%' nowrap>";
echo "			<table cellpadding='0' cellspacing='0' border='0'>";
echo "				<tr>";
echo "					<td valign='middle' nowrap='nowrap' style='padding-right: 15px' id='refresh_state'>";
echo "						<img src='resources/images/refresh_active.gif' style='width: 16px; height: 16px; border: none; margin-top: 3px; cursor: pointer;' onclick='refresh_stop();' alt=\"".$text['label-refresh_pause']."\" title=\"".$text['label-refresh_pause']."\">";
echo "					</td>";

if (permission_exists('operator_panel_eavesdrop')) {
	echo "				<td valign='top' nowrap='nowrap'>";
	if (sizeof($_SESSION['user']['extensions']) > 1) {
		echo "				<input type='hidden' id='eavesdrop_dest' value=\"".(($_REQUEST['eavesdrop_dest'] == '') ? $_SESSION['user']['extension'][0]['destination'] : $_REQUEST['eavesdrop_dest'])."\">";
		echo "				<img src='resources/images/eavesdrop.png' style='width: 12px; height: 12px; border: none; margin: 0px 5px; cursor: help;' title='".$text['description-eavesdrop_destination']."' align='absmiddle'>";
		echo "				<select class='formfld' style='margin-right: 5px;' align='absmiddle' onchange=\"document.getElementById('eavesdrop_dest').value = this.options[this.selectedIndex].value; refresh_start();\" onfocus='refresh_stop();'>\n";
		if (is_array($_SESSION['user']['extensions'])) foreach ($_SESSION['user']['extensions'] as $user_extension) {
			echo "				<option value='".$user_extension."' ".(($_REQUEST['eavesdrop_dest'] == $user_extension) ? "selected" : null).">".$user_extension."</option>\n";
		}
		echo "				</select>\n";
	}
	else if (sizeof($_SESSION['user']['extensions']) == 1) {
		echo "				<input type='hidden' id='eavesdrop_dest' value=\"".$_SESSION['user']['extension'][0]['destination']."\">";
	}
	echo "				</td>";
}

if (sizeof($groups) > 0) {
	echo "				<td valign='top' nowrap='nowrap'>";
	echo "					<input type='hidden' id='group' value=\"".$_REQUEST['group']."\">";
	if (sizeof($groups) > 5) {
		//show select box
		echo "				<select class='formfld' onchange=\"document.getElementById('group').value = this.options[this.selectedIndex].value; refresh_start();\" onfocus='refresh_stop();'>\n";
		echo "					<option value='' ".(($_REQUEST['group'] == '') ? "selected" : null).">".$text['label-call_group']."</option>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -114,30 +114,30 @@
 if (permission_exists('operator_panel_eavesdrop')) {
 	echo "				<td valign='top' nowrap='nowrap'>";
 	if (sizeof($_SESSION['user']['extensions']) > 1) {
-		echo "				<input type='hidden' id='eavesdrop_dest' value=\"".(($_REQUEST['eavesdrop_dest'] == '') ? $_SESSION['user']['extension'][0]['destination'] : $_REQUEST['eavesdrop_dest'])."\">";
+		echo "				<input type='hidden' id='eavesdrop_dest' value=\"".(($_REQUEST['eavesdrop_dest'] == '') ? $_SESSION['user']['extension'][0]['destination'] : escape($_REQUEST['eavesdrop_dest']))."\">";
 		echo "				<img src='resources/images/eavesdrop.png' style='width: 12px; height: 12px; border: none; margin: 0px 5px; cursor: help;' title='".$text['description-eavesdrop_destination']."' align='absmiddle'>";
 		echo "				<select class='formfld' style='margin-right: 5px;' align='absmiddle' onchange=\"document.getElementById('eavesdrop_dest').value = this.options[this.selectedIndex].value; refresh_start();\" onfocus='refresh_stop();'>\n";
 		if (is_array($_SESSION['user']['extensions'])) foreach ($_SESSION['user']['extensions'] as $user_extension) {
-			echo "				<option value='".$user_extension."' ".(($_REQUEST['eavesdrop_dest'] == $user_extension) ? "selected" : null).">".$user_extension."</option>\n";
+			echo "				<option value='".escape($user_extension)."' ".(($_REQUEST['eavesdrop_dest'] == $user_extension) ? "selected" : null).">".escape($user_extension)."</option>\n";
 		}
 		echo "				</select>\n";
 	}
 	else if (sizeof($_SESSION['user']['extensions']) == 1) {
-		echo "				<input type='hidden' id='eavesdrop_dest' value=\"".$_SESSION['user']['extension'][0]['destination']."\">";
+		echo "				<input type='hidden' id='eavesdrop_dest' value=\"".escape($_SESSION['user']['extension'][0]['destination'])."\">";
 	}
 	echo "				</td>";
 }
 
 if (sizeof($groups) > 0) {
 	echo "				<td valign='top' nowrap='nowrap'>";
-	echo "					<input type='hidden' id='group' value=\"".$_REQUEST['group']."\">";
+	echo "					<input type='hidden' id='group' value=\"".escape($_REQUEST['group'])."\">";
 	if (sizeof($groups) > 5) {
 		//show select box
 		echo "				<select class='formfld' onchange=\"document.getElementById('group').value = this.options[this.selectedIndex].value; refresh_start();\" onfocus='refresh_stop();'>\n";
 		echo "					<option value='' ".(($_REQUEST['group'] == '') ? "selected" : null).">".$text['label-call_group']."</option>";
 		echo "					<option value=''>".$text['button-all']."</option>";
 		if (is_array($groups)) foreach ($groups as $group) {
-			echo "				<option value='".$group."' ".(($_REQUEST['group'] == $group) ? "selected" : null).">".$group."</option>\n";
+			echo "				<option value='".escape($group)."' ".(($_REQUEST['group'] == $group) ? "selected" : null).">".escape($group)."</option>\n";
 		}
 		echo "				</select>\n";
 	}
@@ -145,7 +145,7 @@
 		//show buttons
 		echo "				<input type='button' class='btn' title=\"".$text['label-call_group']."\" value=\"".$text['button-all']."\" onclick=\"document.getElementById('group').value = '';\" ".$onhover_pause_refresh.">";
 		if (is_array($groups)) foreach ($groups as $group) {
-			echo "			<input type='button' class='btn' title=\"".$text['label-call_group']."\" value=\"".$group."\" ".(($_REQUEST['group'] == $group) ? "disabled='disabled'" : null)." onclick=\"document.getElementById('group').value = this.value;\" ".$onhover_pause_refresh.">";
+			echo "			<input type='button' class='btn' title=\"".$text['label-call_group']."\" value=\"".escape($group)."\" ".(($_REQUEST['group'] == $group) ? "disabled='disabled'" : null)." onclick=\"document.getElementById('group').value = this.value;\" ".$onhover_pause_refresh.">";
 		}
 	}
 	echo "				</td>";
@@ -309,12 +309,12 @@
 			$status_hover = $text['label-status_logged_out_or_unknown'];
 	}
 
-	$block .= "<div id='".$extension."' class='op_ext ".$style."' ".(($_GET['vd_ext_from'] == $extension || $_GET['vd_ext_to'] == $extension) ? "style='border-style: dotted;'" : null)." ".(($ext_state != 'active' && $ext_state != 'ringing') ? "ondrop='drop(event, this.id);' ondragover='allowDrop(event, this.id);' ondragleave='discardDrop(event, this.id);'" : null).">"; // DRAG TO
+	$block .= "<div id='".escape($extension)."' class='op_ext ".$style."' ".(($_GET['vd_ext_from'] == $extension || $_GET['vd_ext_to'] == $extension) ? "style='border-style: dotted;'" : null)." ".(($ext_state != 'active' && $ext_state != 'ringing') ? "ondrop='drop(event, this.id);' ondragover='allowDrop(event, this.id);' ondragleave='discardDrop(event, this.id);'" : null).">"; // DRAG TO
 	$block .= "<table class='op_ext ".$style."'>";
 	$block .= "	<tr>";
 	$block .= "		<td class='op_ext_icon'>";
-	$block .= "			<span name='".$extension."'>"; // DRAG FROM
-	$block .= 				"<img id='".$call_identifier."' class='op_ext_icon' src='resources/images/status_".$status_icon.".png' title='".$status_hover."' ".(($draggable) ? "draggable='true' ondragstart=\"drag(event, this.parentNode.getAttribute('name'));\" onclick=\"virtual_drag('".$call_identifier."', '".$extension."');\"" : "onfocus='this.blur();' draggable='false' style='cursor: not-allowed;'").">";
+	$block .= "			<span name='".escape($extension)."'>"; // DRAG FROM
+	$block .= 				"<img id='".escape($call_identifier)."' class='op_ext_icon' src='resources/images/status_".$status_icon.".png' title='".$status_hover."' ".(($draggable) ? "draggable='true' ondragstart=\"drag(event, this.parentNode.getAttribute('name'));\" onclick=\"virtual_drag('".escape($call_identifier)."', '".escape($extension)."');\"" : "onfocus='this.blur();' draggable='false' style='cursor: not-allowed;'").">";
 	$block .= 			"</span>";
 	$block .= "		</td>";
 	$block .= "		<td class='op_ext_info ".$style."'>";
@@ -322,22 +322,22 @@
 		$block .= "			<img src='resources/images/".$dir_icon.".png' align='right' style='margin-top: 3px; margin-right: 1px; width: 12px; height: 12px; cursor: help;' draggable='false' alt=\"".$text['label-call_direction']."\" title=\"".$text['label-call_direction']."\">";
 	}
 	$block .= "			<span class='op_user_info'>";
-	if ($ext['effective_caller_id_name'] != '' && $ext['effective_caller_id_name'] != $extension) {
-		$block .= "			<strong class='strong'>".$ext['effective_caller_id_name']."</strong> (".$extension.")";
-	}
-	else {
-		$block .= "			<strong class='strong'>".$extension."</strong>";
+	if ($ext['effective_caller_id_name'] != '' && escape($ext['effective_caller_id_name']) != $extension) {
+		$block .= "			<strong class='strong'>".escape($ext['effective_caller_id_name'])."</strong> (".escape($extension).")";
+	}
+	else {
+		$block .= "			<strong class='strong'>".escape($extension)."</strong>";
 	}
 	$block .= "			</span><br>";
 	if ($ext_state != '') {
 		$block .= "		<span class='op_caller_info'>";
 		$block .= "			<table align='right'><tr><td style='text-align: right;'>";
-		$block .= "				<span class='op_call_info'>".$ext['call_length']."</span><br>";
+		$block .= "				<span class='op_call_info'>".escape($ext['call_length'])."</span><br>";
 		$block .= "				<span class='call_control'>";
 		//record
 		if (permission_exists('operator_panel_record') && $ext_state == 'active') {
 			$call_identifier_record = $ext['call_uuid'];
-			$rec_file = $_SESSION['switch']['recordings']['dir']."/archive/".date("Y")."/".date("M")."/".date("d")."/".$call_identifier_record.".wav";
+			$rec_file = $_SESSION['switch']['recordings']['dir']."/archive/".date("Y")."/".date("M")."/".date("d")."/".escape($call_identifier_record).".wav";
 			if (file_exists($rec_file)) {
 				$block .= 		"<img src='resources/images/recording.png' style='width: 12px; height: 12px; border: none; margin: 4px 0px 0px 5px; cursor: help;' title=\"".$text['label-recording']."\" ".$onhover_pause_refresh.">";
 			}
@@ -347,7 +347,7 @@
 		}
 		//eavesdrop
... (diff truncated)
```
