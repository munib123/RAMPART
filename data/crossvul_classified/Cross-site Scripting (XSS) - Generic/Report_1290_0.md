# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1290_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1290_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 166-206 of the vulnerable file.

	require_once "resources/header.php";
	require_once "resources/paging.php";

//prepare to page the results
	$sql = "select count(*) from v_fax_files ";
	$sql .= "where fax_uuid = :fax_uuid ";
	$sql .= "and domain_uuid = :domain_uuid ";
	if ($_REQUEST['box'] == 'inbox') {
		$sql .= "and fax_mode = 'rx' ";
	}
	if ($_REQUEST['box'] == 'sent') {
		$sql .= "and fax_mode = 'tx' ";
	}
	$parameters['fax_uuid'] = $fax_uuid;
	$parameters['domain_uuid'] = $domain_uuid;
	$database = new database;
	$num_rows = $database->select($sql, $parameters, 'column');

//prepare to page the results
	$rows_per_page = ($_SESSION['domain']['paging']['numeric'] != '') ? $_SESSION['domain']['paging']['numeric'] : 50;
	$param = "&id=".$_GET['id']."&box=".$_GET['box']."&order_by=".$_GET['order_by']."&order=".$_GET['order'];
	$page = $_GET['page'];
	if (strlen($page) == 0) { $page = 0; $_GET['page'] = 0; }
	list($paging_controls, $rows_per_page, $var3) = paging($num_rows, $param, $rows_per_page);
	$offset = $rows_per_page * $page;

//get the list
	$sql = str_replace('count(*)', '*', $sql);
	$sql .= order_by($order_by, $order, 'fax_date', 'desc');
	$sql .= limit_offset($rows_per_page, $offset);
	$database = new database;
	$fax_files = $database->select($sql, $parameters, 'all');
	unset($sql, $parameters, $num_rows);

//show the header
	echo "<table width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
	echo "	<tr>\n";
	echo "		<td align='left' valign='top'>\n";
	if ($_REQUEST['box'] == 'inbox' && permission_exists('fax_inbox_view')) {
		echo "			<b>".$text['header-inbox'].": ".escape($fax_name)." (".escape($fax_extension).")</b>\n";
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -183,7 +183,7 @@
 
 //prepare to page the results
 	$rows_per_page = ($_SESSION['domain']['paging']['numeric'] != '') ? $_SESSION['domain']['paging']['numeric'] : 50;
-	$param = "&id=".$_GET['id']."&box=".$_GET['box']."&order_by=".$_GET['order_by']."&order=".$_GET['order'];
+	$param = "&id=".$fax_uuid."&box=".$_GET['box']."&order_by=".$_GET['order_by']."&order=".$_GET['order'];
 	$page = $_GET['page'];
 	if (strlen($page) == 0) { $page = 0; $_GET['page'] = 0; }
 	list($paging_controls, $rows_per_page, $var3) = paging($num_rows, $param, $rows_per_page);
@@ -223,14 +223,14 @@
 //show the fax files
 	echo "<table class='tr_hover' width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
 	echo "<tr>\n";
-	echo th_order_by('fax_caller_id_name', $text['label-fax_caller_id_name'], $order_by, $order, "&id=".$_GET['id']."&box=".$_GET['box']."&page=".$_GET['page']);
-	echo th_order_by('fax_caller_id_number', $text['label-fax_caller_id_number'], $order_by, $order, "&id=".$_GET['id']."&box=".$_GET['box']."&page=".$_GET['page']);
+	echo th_order_by('fax_caller_id_name', $text['label-fax_caller_id_name'], $order_by, $order, "&id=".$fax_uuid."&box=".$_GET['box']."&page=".$_GET['page']);
+	echo th_order_by('fax_caller_id_number', $text['label-fax_caller_id_number'], $order_by, $order, "&id=".$fax_uuid."&box=".$_GET['box']."&page=".$_GET['page']);
 	if ($_REQUEST['box'] == 'sent') {
-		echo th_order_by('fax_destination', $text['label-fax_destination'], $order_by, $order, "&id=".$_GET['id']."&box=".$_GET['box']."&page=".$_GET['page']);
+		echo th_order_by('fax_destination', $text['label-fax_destination'], $order_by, $order, "&id=".$fax_uuid."&box=".$_GET['box']."&page=".$_GET['page']);
 	}
 	echo "<th width=''>".$text['table-file']."</th>\n";
 	echo "<th width='10%'>".$text['table-view']."</th>\n";
-	echo th_order_by('fax_date', $text['label-fax_date'], $order_by, $order, "&id=".$_GET['id']."&box=".$_GET['box']."&page=".$_GET['page']);
+	echo th_order_by('fax_date', $text['label-fax_date'], $order_by, $order, "&id=".$fax_uuid."&box=".$_GET['box']."&page=".$_GET['page']);
 	echo "<td style='width: 25px;' class='list_control_icons'>&nbsp;</td>\n";
 	echo "</tr>\n";
 	if (is_array($fax_files) && @sizeof($fax_files) != 0) {
@@ -324,10 +324,10 @@
 			}
 			echo "  <td class='".$row_style[$c]."' ondblclick=\"\">\n";
 			if ($_REQUEST['box'] == 'inbox' && permission_exists('fax_inbox_view')) {
-				echo "	  <a href=\"fax_files.php?id=".$fax_uuid."&a=download&type=fax_inbox&t=bin&ext=".escape(urlencode($fax_extension))."&filename=".escape(urlencode($file))."\">\n";
+				echo "	  <a href=\"fax_files.php?id=".urlencode($fax_uuid)."&a=download&type=fax_inbox&t=bin&ext=".urlencode($fax_extension)."&filename=".urlencode($file)."\">\n";
 			}
 			if ($_REQUEST['box'] == 'sent' && permission_exists('fax_sent_view')) {
-				echo "	  <a href=\"fax_files.php?id=".$fax_uuid."&a=download&type=fax_sent&t=bin&ext=".escape(urlencode($fax_extension))."&filename=".escape(urlencode($file))."\">\n";
+				echo "	  <a href=\"fax_files.php?id=".urlencode($fax_uuid)."&a=download&type=fax_sent&t=bin&ext=".urlencode($fax_extension)."&filename=".urlencode($file)."\">\n";
 			}
 			echo "    	$file_name";
 			echo "	  </a>";
@@ -341,10 +341,10 @@
 			}
 			if (file_exists($dir_fax.'/'.$file_name.".pdf")) {
 				if ($_REQUEST['box'] == 'inbox' && permission_exists('fax_inbox_view')) {
-					echo "	  <a href=\"fax_files.php?id=".escape($fax_uuid)."&a=download&type=fax_inbox&t=bin&ext=".escape(urlencode($fax_extension))."&filename=".escape(urlencode($file_name)).".pdf\">PDF</a>\n";
+					echo "	  <a href=\"fax_files.php?id=".urlencode($fax_uuid)."&a=download&type=fax_inbox&t=bin&ext=".urlencode($fax_extension)."&filename=".urlencode($file_name).".pdf\">PDF</a>\n";
 				}
 				if ($_REQUEST['box'] == 'sent' && permission_exists('fax_sent_view')) {
-					echo "	  <a href=\"fax_files.php?id=".escape($fax_uuid)."&a=download&type=fax_sent&t=bin&ext=".escape(urlencode($fax_extension))."&filename=".escape(urlencode($file_name)).".pdf\">PDF</a>\n";
+					echo "	  <a href=\"fax_files.php?id=".urlencode($fax_uuid)."&a=download&type=fax_sent&t=bin&ext=".urlencode($fax_extension)."&filename=".urlencode($file_name).".pdf\">PDF</a>\n";
 				}
 			}
 			else {
@@ -356,7 +356,7 @@
 			echo "	<td valign='top' class='".$row_style[$c]."'>".$fax_date."&nbsp;</td>\n";
 			echo "	<td style='width: 25px;' class='list_control_icons'>";
 			if (permission_exists('fax_file_delete')) {
-				echo "<a href='fax_file_delete.php?id=".escape($row['fax_file_uuid'])."' alt='".$text['button-delete']."' onclick=\"return confirm('".$text['confirm-delete']."')\">$v_link_label_delete</a>";
+				echo "<a href='fax_file_delete.php?id=".urlencode($row['fax_file_uuid'])."' alt='".$text['button-delete']."' onclick=\"return confirm('".$text['confirm-delete']."')\">$v_link_label_delete</a>";
 			}
 			echo "	</td>\n";
 			echo "</tr>\n";
```
