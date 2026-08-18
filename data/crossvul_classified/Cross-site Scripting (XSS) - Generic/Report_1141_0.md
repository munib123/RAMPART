# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1141_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1141_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

	the Initial Developer. All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/

//includes
	require_once "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (permission_exists('contact_time_view')) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

//get the contact list
	$sql = "select ct.*, u.username, u.domain_uuid as user_domain_uuid ";
	$sql .= "from v_contact_times as ct, v_users as u ";
	$sql .= "where ct.user_uuid = u.user_uuid ";
	$sql .= "and ct.domain_uuid = :domain_uuid ";
	$sql .= "and ct.contact_uuid = :contact_uuid ";
	$sql .= "order by ct.time_start desc ";
	$parameters['domain_uuid'] = $domain_uuid;
	$parameters['contact_uuid'] = $contact_uuid;
	$database = new database;
	$result = $database->select($sql, $parameters, 'all');
	unset($sql, $parameters);

//set the row style
	$c = 0;
	$row_style["0"] = "row_style0";
	$row_style["1"] = "row_style1";

//show the content
	echo "<table width='100%' border='0'>\n";
	echo "<tr>\n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,11 @@
 		exit;
 	}
 
+//set the uuid
+	if (is_uuid($_GET['id'])) {
+		$contact_uuid = $_GET['id'];
+	}
+
 //get the contact list
 	$sql = "select ct.*, u.username, u.domain_uuid as user_domain_uuid ";
 	$sql .= "from v_contact_times as ct, v_users as u ";
@@ -74,7 +79,7 @@
 	echo "<td class='list_control_icons' nowrap>";
 	echo 	img_spacer('25px', '1px');
 	if (permission_exists('contact_time_add')) {
-		echo "<a href='contact_time_edit.php?contact_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "<a href='contact_time_edit.php?contact_uuid=".urlencode($contact_uuid)."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	else {
 		echo img_spacer('25px', '1px');
```
