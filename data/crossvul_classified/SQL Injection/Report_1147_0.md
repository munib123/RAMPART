# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1147_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1147_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 80-120 of the vulnerable file.

//show the content
	echo "<table width='100%' cellpadding='0' cellspacing='0' border='0'><tr>\n";
	echo "<td width='50%' nowrap='nowrap' align='left'><b>".$text['title']."</b></td>\n";
	echo "<td width='50%' align='right'>&nbsp;</td>\n";
	echo "</tr></table>\n";
	echo "<br>";

	echo "<table class='tr_hover' width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
	echo "<tr>\n";
	echo th_order_by('broadcast_name', $text['label-name'], $order_by, $order);
	echo th_order_by('broadcast_concurrent_limit', $text['label-concurrent-limit'], $order_by, $order);
	echo th_order_by('broadcast_description', $text['label-description'], $order_by, $order);
	//echo th_order_by('recordingid', 'Recording', $order_by, $order);
	echo "<td class='list_control_icons'>";
	if (permission_exists('call_broadcast_add')) {
		echo "<a href='call_broadcast_edit.php' alt='add'>$v_link_label_add</a>";
	}
	echo "</td>\n";
	echo "</tr>\n";

	if (is_array($result)) {
		foreach($result as $row) {
			$tr_link = (permission_exists('call_broadcast_edit')) ? "href='call_broadcast_edit.php?id=".$row['call_broadcast_uuid']."'" : null;
			echo "<tr ".$tr_link.">\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>";
			if (permission_exists('call_broadcast_edit')) {
				echo "<a href='call_broadcast_edit.php?id=".escape($row['call_broadcast_uuid'])."'>".escape($row['broadcast_name'])."</a>";
			}
			else {
				echo escape($row['broadcast_name']);
			}
			echo "	</td>\n";
			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['broadcast_concurrent_limit'])."&nbsp;</td>\n";
			//echo "	<td valign='top' class='".$row_style[$c]."'>".$row['recordingid']."</td>\n";
			echo "	<td valign='top' class='row_stylebg'>".escape($row['broadcast_description'])."&nbsp;</td>\n";
			echo "	<td class='list_control_icons'>";
			if (permission_exists('call_broadcast_edit')) {
				echo "<a href='call_broadcast_edit.php?id=".escape($row['call_broadcast_uuid'])."' alt='".$text['button-edit']."'>$v_link_label_edit</a>";
			}
			if (permission_exists('call_broadcast_delete')) {
				echo "<a href='call_broadcast_delete.php?id=".escape($row['call_broadcast_uuid'])."' alt='".$text['button-delete']."' onclick=\"return confirm('".$text['confirm-delete-info']."')\">$v_link_label_delete</a>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,7 @@
 	echo "</td>\n";
 	echo "</tr>\n";
 
-	if (is_array($result)) {
+	if (is_array($result) && @sizeof($result) != 0) {
 		foreach($result as $row) {
 			$tr_link = (permission_exists('call_broadcast_edit')) ? "href='call_broadcast_edit.php?id=".$row['call_broadcast_uuid']."'" : null;
 			echo "<tr ".$tr_link.">\n";
@@ -122,9 +122,9 @@
 			echo "	</td>\n";
 			echo "</tr>\n";
 			if ($c==0) { $c=1; } else { $c=0; }
-		} //end foreach
-		unset($sql, $result, $row_count);
-	} //end if results
+		}
+	}
+	unset($sql, $result);
 
 	echo "<tr>\n";
 	echo "<td colspan='5' align='left'>\n";
```
