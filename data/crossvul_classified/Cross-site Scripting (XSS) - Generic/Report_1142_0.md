# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1142_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1142_0`)

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
	if (permission_exists('contact_note_view')) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

//show the content
	echo "<table width='100%' border='0'>\n";
	echo "<tr>\n";
	echo "<td width='50%' align='left' nowrap='nowrap'><b>".$text['label-contact_notes']."</b></td>\n";
	echo "<td width='50%' align='right'>&nbsp;</td>\n";
	echo "</tr>\n";
	echo "</table>\n";

//get the contact list
	$sql = "select * from v_contact_notes ";
	$sql .= "where domain_uuid = :domain_uuid ";
	$sql .= "and contact_uuid = :contact_uuid ";
	$sql .= "order by last_mod_date desc ";
	$parameters['domain_uuid'] = $_SESSION['domain_uuid'];
	$parameters['contact_uuid'] = $contact_uuid;
	$database = new database;
	$contact_notes = $database->select($sql, $parameters, 'all');
	unset($sql, $parameters);

//set the row style array
	$c = 0;
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
@@ -70,7 +75,7 @@
 	echo "<th style='text-align: right;'>".$text['label-note_user']."</th>\n";
 	echo "<td class='list_control_icons'>";
 	if (permission_exists('contact_note_add')) {
-		echo "<a href='contact_note_edit.php?contact_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "<a href='contact_note_edit.php?contact_uuid=".urlencode($contact_uuid)."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	echo "</td>\n";
 	echo "</tr>\n";
```
