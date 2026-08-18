# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1148_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1148_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 56-96 of the vulnerable file.

	$row_style["0"] = "row_style0";
	$row_style["1"] = "row_style1";

//show the content
	echo "<table width='100%' border='0'>\n";
	echo "	<tr>\n";
	echo "		<td align='left' colspan='2'>\n";
	echo "			".$text['title_description-conference_profile_param']."<br /><br />\n";
	echo "		</td>\n";
	echo "	</tr>\n";
	echo "</table>\n";

	echo "<table class='tr_hover' width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
	echo "<tr>\n";
	echo th_order_by('profile_param_name', $text['label-profile_param_name'], $order_by, $order);
	echo th_order_by('profile_param_value', $text['label-profile_param_value'], $order_by, $order);
	echo th_order_by('profile_param_enabled', $text['label-profile_param_enabled'], $order_by, $order);
	echo th_order_by('profile_param_description', $text['label-profile_param_description'], $order_by, $order);
	echo "<td class='list_control_icons'>";
	if (permission_exists('conference_profile_param_add')) {
		echo "<a href='conference_profile_param_edit.php?conference_profile_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
	}
	else {
		echo "&nbsp;\n";
	}
	echo "</td>\n";
	echo "<tr>\n";

	if (is_array($result) && sizeof($result) != 0) {
		foreach($result as $row) {
			if (permission_exists('conference_profile_param_edit')) {
				$tr_link = "href='conference_profile_param_edit.php?conference_profile_uuid=".$row['conference_profile_uuid']."&id=".$row['conference_profile_param_uuid']."'";
			}
			echo "<tr ".$tr_link.">\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['profile_param_name'])."&nbsp;</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['profile_param_value'])."&nbsp;</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['profile_param_enabled'])."&nbsp;</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['profile_param_description'])."&nbsp;</td>\n";
			echo "	<td class='list_control_icons'>";
			if (permission_exists('conference_profile_param_edit')) {
				echo "<a href='conference_profile_param_edit.php?conference_profile_uuid=".escape($row['conference_profile_uuid'])."&id=".escape($row['conference_profile_param_uuid'])."' alt='".$text['button-edit']."'>$v_link_label_edit</a>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,7 @@
 	echo th_order_by('profile_param_description', $text['label-profile_param_description'], $order_by, $order);
 	echo "<td class='list_control_icons'>";
 	if (permission_exists('conference_profile_param_add')) {
-		echo "<a href='conference_profile_param_edit.php?conference_profile_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "<a href='conference_profile_param_edit.php?conference_profile_uuid=".escape($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	else {
 		echo "&nbsp;\n";
@@ -113,7 +113,7 @@
 	echo "		<td width='33.3%' align='center' nowrap='nowrap'>$paging_controls</td>\n";
 	echo "		<td class='list_control_icons'>";
 	if (permission_exists('conference_profile_param_add')) {
-		echo 		"<a href='conference_profile_param_edit.php?conference_profile_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo 		"<a href='conference_profile_param_edit.php?conference_profile_uuid=".escape($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	else {
 		echo 		"&nbsp;";
```
