# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1139_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1139_0`)

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
	if (permission_exists('contact_address_view')) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

//show the content
	echo "<table width='100%' border='0'>\n";
	echo "<tr>\n";
	echo "<td width='50%' align='left' nowrap='nowrap'><b>".$text['label-addresses']."</b></td>\n";
	echo "<td width='50%' align='right'>&nbsp;</td>\n";
	echo "</tr>\n";
	echo "</table>\n";

	//get the contact list
		$sql = "select * from v_contact_addresses ";
		$sql .= "where domain_uuid = :domain_uuid ";
		$sql .= "and contact_uuid = :contact_uuid ";
		$sql .= "order by address_primary desc, address_label asc ";
		$parameters['domain_uuid'] = $_SESSION['domain_uuid'];
		$parameters['contact_uuid'] = $contact_uuid;
		$database = new database;
		$result = $database->select($sql, $parameters, 'all');
		unset($sql, $parameters);

	$c = 0;
	$row_style["0"] = "row_style0";
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
 //show the content
 	echo "<table width='100%' border='0'>\n";
 	echo "<tr>\n";
@@ -46,21 +51,23 @@
 	echo "</tr>\n";
 	echo "</table>\n";
 
-	//get the contact list
-		$sql = "select * from v_contact_addresses ";
-		$sql .= "where domain_uuid = :domain_uuid ";
-		$sql .= "and contact_uuid = :contact_uuid ";
-		$sql .= "order by address_primary desc, address_label asc ";
-		$parameters['domain_uuid'] = $_SESSION['domain_uuid'];
-		$parameters['contact_uuid'] = $contact_uuid;
-		$database = new database;
-		$result = $database->select($sql, $parameters, 'all');
-		unset($sql, $parameters);
+//get the contact list
+	$sql = "select * from v_contact_addresses ";
+	$sql .= "where domain_uuid = :domain_uuid ";
+	$sql .= "and contact_uuid = :contact_uuid ";
+	$sql .= "order by address_primary desc, address_label asc ";
+	$parameters['domain_uuid'] = $_SESSION['domain_uuid'];
+	$parameters['contact_uuid'] = $contact_uuid;
+	$database = new database;
+	$result = $database->select($sql, $parameters, 'all');
+	unset($sql, $parameters);
 
+//set the row style
 	$c = 0;
 	$row_style["0"] = "row_style0";
 	$row_style["1"] = "row_style1";
 
+//show the content
 	echo "<table class='tr_hover' style='margin-bottom: 20px;' width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
 
 	echo "<tr>\n";
@@ -72,7 +79,7 @@
 	echo "<th>".$text['label-address_description']."</th>\n";
 	echo "<td class='list_control_icons'>";
 	if (permission_exists('contact_address_add')) {
-		echo "<a href='contact_address_edit.php?contact_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "<a href='contact_address_edit.php?contact_uuid=".urlencode($contact_uuid)."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	echo "</td>\n";
 	echo "</tr>\n";
```
