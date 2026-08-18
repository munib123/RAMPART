# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4845_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4845_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php
	/*
		Class: BTXFormBuilder
			Provides an interface for form builder data.
	*/

	class BTXFormBuilder extends BigTreeModule {
		var $Table = "btx_form_builder_forms";
		static $SearchPageCount = false;
		
		/*
			Function: getForm
				Gets form information and related fields.

			Parameters:
				id - The form ID
			
			Returns:
				A form array or false if the form doesn't exist.
		*/

		static function getForm($id) {
			$id = sqlescape($id);
			$form = sqlfetch(sqlquery("SELECT * FROM btx_form_builder_forms WHERE id = '$id'"));
			if (!$form) {
				return false;
			}

			$fields = array();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,8 +5,9 @@
 	*/
 
 	class BTXFormBuilder extends BigTreeModule {
-		var $Table = "btx_form_builder_forms";
-		static $SearchPageCount = false;
+		public $Table = "btx_form_builder_forms";
+
+		public static $SearchPageCount = false;
 		
 		/*
 			Function: getForm
@@ -29,6 +30,7 @@
 			$fields = array();
 			$object_count = 0;
 			$field_query = sqlquery("SELECT * FROM btx_form_builder_fields WHERE form = '$id' AND `column` = '0' ORDER BY position DESC, id ASC");
+			
 			while ($field = sqlfetch($field_query)) {
 				$object_count++;
 
@@ -36,20 +38,24 @@
 					// Get left column
 					$column_fields = array();
 					$column_query = sqlquery("SELECT * FROM btx_form_builder_fields WHERE `column` = '".$field["id"]."' AND `alignment` = 'left' ORDER BY position DESC, id ASC");
+					
 					while ($sub_field = sqlfetch($column_query)) {
 						$column_fields[] = $sub_field;
 						$object_count++;
 					}
+
 					$field["fields"] = $column_fields;
 					$fields[] = $field;
 
 					// Get right column
 					$column_fields = array();
 					$column_query = sqlquery("SELECT * FROM btx_form_builder_fields WHERE `column` = '".$field["id"]."' AND `alignment` = 'right' ORDER BY position DESC, id ASC");
+					
 					while ($sub_field = sqlfetch($column_query)) {
 						$column_fields[] = $sub_field;
 						$object_count++;
 					}
+					
 					$field["fields"] = $column_fields;
 					$fields[] = $field;
 
@@ -62,6 +68,7 @@
 
 			$form["fields"] = $fields;
 			$form["object_count"] = $object_count - 1; // We start at 0
+
 			return $form;
 		}
 
@@ -78,6 +85,7 @@
 		
 		static function getAllForms($sort = "id ASC") {
 			$mod = new BigTreeModule("btx_form_builder_forms");
+
 			return $mod->getAll($sort);
 		}
 
@@ -94,6 +102,7 @@
 		
 		static function getEntries($id) {
 			$mod = new BigTreeModule("btx_form_builder_entries");
+
 			return $mod->getMatching("form",$id,"id DESC");
 		}
 
```
