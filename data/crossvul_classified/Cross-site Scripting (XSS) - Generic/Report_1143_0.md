# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1143_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1143_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 450-490 of the vulnerable file.

				//save to the data
					if (is_array($array)) {
						$database = new database;
						$database->app_name = 'destinations';
						$database->app_uuid = '5ec89622-b19c-3559-64f0-afde802ab139';
						$database->save($array);
						$message = $database->message;
					}

				//send the redirect header
					header("Location: destinations.php");
					return;
			}

		//show the header
			require_once "resources/header.php";
			echo "<table width='100%' border='0' cellpadding='0' cellspacing='0'>\n";
			echo "<tr>\n";
			echo "<td align='left' width='30%' nowrap='nowrap'><b>".$text['header-destinations_import']."</b></td>\n";
			echo "<td width='70%' align='right'>\n";
			echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='/app/destinations/destinations.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
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
			echo "	<th>".$text['label-destination_name']."</th>\n";
			echo "	<th>".$text['label-destination_organization']."</th>\n";
			//echo "	<th>".$text['label-destination_email']."</th>\n";
			echo "	<th>".$text['label-destination_url']."</th>\n";
			echo "</tr>\n";
			if ($results) {
				foreach($results as $row) {
					echo "<tr>\n";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -467,7 +467,7 @@
 			echo "<tr>\n";
 			echo "<td align='left' width='30%' nowrap='nowrap'><b>".$text['header-destinations_import']."</b></td>\n";
 			echo "<td width='70%' align='right'>\n";
-			echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='/app/destinations/destinations.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
+			echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='/app/destinations/destinations.php'\" value='".$text['button-back']."'>\n";
 			echo "</td>\n";
 			echo "</tr>\n";
 			echo "<tr>\n";
@@ -937,7 +937,7 @@
 	echo "		".$text['description-destination_import']."\n";
 	echo "	</td>\n";
 	echo "	<td valign='top' width='70%' align='right'>\n";
-	echo "		<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='/app/destinations/destinations.php?".$_GET["query_string"]."'\" value='".$text['button-back']."'>\n";
+	echo "		<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='/app/destinations/destinations.php'\" value='".$text['button-back']."'>\n";
 	//echo "		<input name='submit' type='submit' class='btn' id='import' value=\"".$text['button-import']."\">\n";
 	echo "	</td>\n";
 	echo "	</tr>\n";
```
