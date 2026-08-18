# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1155_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1155_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 362-402 of the vulnerable file.

				//save to the data
					if (is_array($array)) {
						$database = new database;
						$database->app_name = 'contacts';
						$database->app_uuid = '04481e0e-a478-c559-adad-52bd4174574c';
						$database->save($array);
						unset($array);
					}

				//send the redirect header
					header("Location: contacts.php");
					exit;
			}

		//show the header
			require_once "resources/header.php";
			echo "<table width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
			echo "<tr>\n";
			echo "<td align='left' width='30%' nowrap='nowrap'><b>".$text['header-contacts_import']."</b></td>\n";
			echo "<td width='70%' align='right'>\n";
			echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
			echo "</td>\n";
			echo "</tr>\n";
			echo "<tr>\n";
			echo "<td align='left' colspan='2'>\n";
			echo "	".$text['message-results']."<br /><br />\n";
			echo "</td>\n";
			echo "</tr>\n";
			echo "</table>\n";

		//show the results
			echo "<table width='100%'  border='0' cellpadding='0' cellspacing='0' width='100%'>\n";
			echo "<tr>\n";
			echo "	<th>".$text['label-contact_name']."</th>\n";
			echo "	<th>".$text['label-contact_organization']."</th>\n";
			//echo "	<th>".$text['label-contact_email']."</th>\n";
			echo "	<th>".$text['label-contact_url']."</th>\n";
			echo "</tr>\n";
			if ($results) {
				foreach($results as $row) {
					echo "<tr>\n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -379,7 +379,7 @@
 			echo "<tr>\n";
 			echo "<td align='left' width='30%' nowrap='nowrap'><b>".$text['header-contacts_import']."</b></td>\n";
 			echo "<td width='70%' align='right'>\n";
-			echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
+			echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php'\" value='".$text['button-back']."'>\n";
 			echo "</td>\n";
 			echo "</tr>\n";
 			echo "<tr>\n";
@@ -433,7 +433,7 @@
 	echo "		".$text['description-contacts_import']."\n";
 	echo "	</td>\n";
 	echo "	<td valign='top' width='70%' align='right'>\n";
-	echo "		<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
+	echo "		<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='contacts.php'\" value='".$text['button-back']."'>\n";
 	//echo "		<input name='submit' type='submit' class='btn' id='import' value=\"".$text['button-import']."\">\n";
 	echo "	</td>\n";
 	echo "	</tr>\n";
```
