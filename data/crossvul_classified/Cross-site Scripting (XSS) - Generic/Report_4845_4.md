# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4845_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4845_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 72-112 of the vulnerable file.

				$error = false;
				
				if (isset($_SESSION["form_builder"]["fields"])) {
					$default = $_SESSION["form_builder"]["fields"][$field_name];
				} else {
					if (isset($field_data["default"])) {
						$default = $field_data["default"];
					} else {
						$default = false;
					}
				}
				
				if (is_array($_SESSION["form_builder"]["errors"]) && in_array($field_name,$_SESSION["form_builder"]["errors"])) {
					$error = true;
				}
				
				include "field-types/draw/$field_type.php";
			} else {
				if ($last_field == "column") {
					echo '<div class="form_builder_column form_builder_last">';
				} else {
					echo '<div class="form_builder_column">';
				}
				
				foreach ($field["fields"] as $subfield) {
					$count++;
					$field_data = json_decode($subfield["data"],true);
					
					if ($field_data["name"]) {
						$field_name = $field_data["name"];
					} else {
						$field_name = "data_".$subfield["id"];
					}
					
					$error = false;
					
					if (isset($_SESSION["form_builder"]["fields"])) {
						$default = $_SESSION["form_builder"]["fields"][$field_name];
					} else {
						if (isset($field_data["default"])) {
							$default = $field_data["default"];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,6 +89,9 @@
 			} else {
 				if ($last_field == "column") {
 					echo '<div class="form_builder_column form_builder_last">';
+
+					// Reset so that if someone did back to back columns it draws properly
+					$field_type = "second_column";
 				} else {
 					echo '<div class="form_builder_column">';
 				}
@@ -124,6 +127,7 @@
 				
 				echo '</div>';
 			}
+
 			$last_field = $field_type;
 		}
 	?>
```
