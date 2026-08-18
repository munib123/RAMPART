# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1135_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1135_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 75-115 of the vulnerable file.

	echo "<table width='100%' border='0'>\n";
	echo "	<tr>\n";
	echo "		<td width='50%' align='left' nowrap='nowrap'><b>".$text['title-conference_control_details']."</b></td>\n";
	//echo "		<form method='get' action=''>\n";
	//echo "			<td width='50%' style='vertical-align: top; text-align: right; white-space: nowrap;'>\n";
	//echo "				<input type='text' class='txt' style='width: 150px' name='search' id='search' value='".escape($search)."'>\n";
	//echo "				<input type='submit' class='btn' name='submit' value='".$text['button-search']."'>\n";
	//echo "			</td>\n";
	//echo "		</form>\n";
	echo "	</tr>\n";
	echo "</table>\n";

	echo "<table class='tr_hover' width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
	echo "<tr>\n";
	echo th_order_by('control_digits', $text['label-control_digits'], $order_by, $order);
	echo th_order_by('control_action', $text['label-control_action'], $order_by, $order);
	echo th_order_by('control_data', $text['label-control_data'], $order_by, $order);
	echo th_order_by('control_enabled', $text['label-control_enabled'], $order_by, $order);
	echo "<td class='list_control_icons'>";
	if (permission_exists('conference_control_detail_add')) {
		echo "<a href='conference_control_detail_edit.php?conference_control_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
	}
	else {
		echo "&nbsp;\n";
	}
	echo "</td>\n";
	echo "<tr>\n";

	if (is_array($result) && sizeof($result) != 0) {
		foreach($result as $row) {
			if (permission_exists('conference_control_detail_edit')) {
				$tr_link = "href='conference_control_detail_edit.php?conference_control_uuid=".escape($row['conference_control_uuid'])."&id=".escape($row['conference_control_detail_uuid'])."'";
			}
			echo "<tr ".$tr_link.">\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['control_digits'])."&nbsp;</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['control_action'])."&nbsp;</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['control_data'])."&nbsp;</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['control_enabled'])."&nbsp;</td>\n";
			echo "	<td class='list_control_icons'>";
			if (permission_exists('conference_control_detail_edit')) {
				echo "<a href='conference_control_detail_edit.php?conference_control_uuid=".escape($row['conference_control_uuid'])."&id=".escape($row['conference_control_detail_uuid'])."' alt='".$text['button-edit']."'>$v_link_label_edit</a>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,7 +92,7 @@
 	echo th_order_by('control_enabled', $text['label-control_enabled'], $order_by, $order);
 	echo "<td class='list_control_icons'>";
 	if (permission_exists('conference_control_detail_add')) {
-		echo "<a href='conference_control_detail_edit.php?conference_control_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "<a href='conference_control_detail_edit.php?conference_control_uuid=".escape($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	else {
 		echo "&nbsp;\n";
@@ -132,7 +132,7 @@
 	echo "		<td width='33.3%' align='center' nowrap='nowrap'>$paging_controls</td>\n";
 	echo "		<td class='list_control_icons'>";
 	if (permission_exists('conference_control_detail_add')) {
-		echo 		"<a href='conference_control_detail_edit.php?conference_control_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo 		"<a href='conference_control_detail_edit.php?conference_control_uuid=".escape($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	else {
 		echo 		"&nbsp;";
```
