# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1140_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1140_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 329-369 of the vulnerable file.

	echo "	});";
	echo "</script>";
	if (isset($_SESSION['theme']['qr_image'])) {
		echo "<img id='img-buffer' src='".$_SESSION["theme"]["qr_image"]["text"]."' style='display: none;'>";
	}
	else {
		echo "<img id='img-buffer' src='".PROJECT_PATH."/themes/".$_SESSION["domain"]["template"]["name"]."/images/qr_code.png' style='display: none;'>";
	}

//show the content
	echo "<form method='post' name='frm' action=''>\n";
	echo "<table width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
	echo "<tr>\n";
	echo "<td valign='top' align='left' width='30%' nowrap='nowrap'><b>";
	switch ($action) {
		case "add": echo $text['header-contact-add']; break;
		case "update": echo $text['header-contact-edit']; break;
	}
	echo "</b></td>\n";
	echo "<td valign='top' width='70%' align='right'>\n";
	echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
	if ($action == "update") {
		if (permission_exists('contact_time_add')) {
			//detect timer state (and start time)
			$sql = "select ";
			$sql .= "time_start ";
			$sql .= "from v_contact_times ";
			$sql .= "where domain_uuid = :domain_uuid ";
			$sql .= "and user_uuid = :user_uuid ";
			$sql .= "and contact_uuid = :contact_uuid ";
			$sql .= "and time_start is not null ";
			$sql .= "and time_stop is null ";
			$parameters['domain_uuid'] = $_SESSION['domain_uuid'];
			$parameters['user_uuid'] = $_SESSION['user']['user_uuid'];
			$parameters['contact_uuid'] = $contact_uuid;
			$database = new database;
			$time_start = $database->select($sql, $parameters, 'column');
			$btn_mod = $time_start != '' ? "style='background-color: #3693df; background-image: none;'" : null;
			unset($sql, $parameters);
			echo "	<input type='button' class='btn' ".$btn_mod." alt='".$text['button-timer']."' ".($time_start != '' ? "title='".escape($time_start)."'" : null)." onclick=\"window.open('contact_timer.php?domain_uuid=".escape($domain_uuid)."&contact_uuid=".escape($contact_uuid)."','contact_time_".escape($contact_uuid)."','width=300, height=375, top=30, left='+(screen.width - 350)+', menubar=no, scrollbars=no, status=no, toolbar=no, resizable=no');\" value='".$text['button-timer']."'>\n";
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -346,7 +346,7 @@
 	}
 	echo "</b></td>\n";
 	echo "<td valign='top' width='70%' align='right'>\n";
-	echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
+	echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php'\" value='".$text['button-back']."'>\n";
 	if ($action == "update") {
 		if (permission_exists('contact_time_add')) {
 			//detect timer state (and start time)
```
