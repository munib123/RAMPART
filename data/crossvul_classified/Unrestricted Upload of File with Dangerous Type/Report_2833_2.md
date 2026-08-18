# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 2833_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2833_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 171-211 of the vulnerable file.

    }
    if (apikey_checker($GLOBALS['apikey'])) {
        include "../sources/main.functions.php";
        teampass_connect();
        $category_query = "";

        if ($GLOBALS['request'][0] == "write") {
            if ($GLOBALS['request'][1] == "category") {
                $array_category = explode(';', $GLOBALS['request'][2]);

                foreach ($array_category as $category) {
                    if (!preg_match_all("/^([\w\:\'\-\sàáâãäåçèéêëìíîïðòóôõöùúûüýÿ]+)$/i", $category, $result)) {
                        rest_error('CATEGORY_MALFORMED');
                    }
                }

                if (count($array_category) > 1 && count($array_category) < 5) {
                    for ($i = count($array_category); $i > 0; $i--) {
                        $slot = $i - 1;
                        if (!$slot) {
                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[$slot]."' AND parent_id = 0";
                        } else {
                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[$slot]."' AND parent_id = (";
                        }
                    }
                    for ($i = 1; $i < count($array_category); $i++) {
                        $category_query .= ")";
                    }
                } elseif (count($array_category) == 1) {
                    $category_query = "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[0]."' AND parent_id = 0";
                } else {
                    rest_error('NO_CATEGORY');
                }

                // Delete items which in category
                $response = DB::delete(prefix_table("items"), "id_tree = (".$category_query.")");
                // Delete sub-categories which in category
                $response = DB::delete(prefix_table("nested_tree"), "parent_id = (".$category_query.")");
                // Delete category
                $response = DB::delete(prefix_table("nested_tree"), "id = (".$category_query.")");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,16 +188,16 @@
                     for ($i = count($array_category); $i > 0; $i--) {
                         $slot = $i - 1;
                         if (!$slot) {
-                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[$slot]."' AND parent_id = 0";
+                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".filter_var($array_category[$slot], FILTER_SANITIZE_STRING)."' AND parent_id = 0";
                         } else {
-                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[$slot]."' AND parent_id = (";
+                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".filter_var($array_category[$slot], FILTER_SANITIZE_STRING)."' AND parent_id = (";
                         }
                     }
                     for ($i = 1; $i < count($array_category); $i++) {
                         $category_query .= ")";
                     }
                 } elseif (count($array_category) == 1) {
-                    $category_query = "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[0]."' AND parent_id = 0";
+                    $category_query = "select id from ".prefix_table("nested_tree")." where title LIKE '".filter_var($array_category[0], FILTER_SANITIZE_STRING)."' AND parent_id = 0";
                 } else {
                     rest_error('NO_CATEGORY');
                 }
@@ -236,22 +236,22 @@
                     for ($i = count($array_category); $i > 0; $i--) {
                         $slot = $i - 1;
                         if (!$slot) {
-                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[$slot]."' AND parent_id = 0";
+                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".filter_var($array_category[$slot], FILTER_SANITIZE_STRING)."' AND parent_id = 0";
                         } else {
-                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[$slot]."' AND parent_id = (";
+                            $category_query .= "select id from ".prefix_table("nested_tree")." where title LIKE '".filter_var($array_category[$slot], FILTER_SANITIZE_STRING)."' AND parent_id = (";
                         }
                     }
                     for ($i = 1; $i < count($array_category); $i++) {
                         $category_query .= ")";
                     }
                 } elseif (count($array_category) == 1) {
-                    $category_query = "select id from ".prefix_table("nested_tree")." where title LIKE '".$array_category[0]."' AND parent_id = 0";
+                    $category_query = "select id from ".prefix_table("nested_tree")." where title LIKE '".filter_var($array_category[0], FILTER_SANITIZE_STRING)."' AND parent_id = 0";
                 } else {
                     rest_error('NO_CATEGORY');
                 }
 
                 // Delete item
-                $response = DB::delete(prefix_table("items"), "id_tree = (".$category_query.") and label LIKE '".$item."'");
+                $response = DB::delete(prefix_table("items"), "id_tree = (".$category_query.") and label LIKE '".filter_var($item, FILTER_SANITIZE_STRING)."'");
                 $json['type'] = 'item';
                 $json['item'] = $item;
                 $json['category'] = $GLOBALS['request'][2];
@@ -382,7 +382,12 @@
                 if (strcmp($username, "admin") == 0) {
                     // forbid admin access
                 }
-                $response = DB::query("SELECT fonction_id FROM ".prefix_table("users")." WHERE login='".$username."'");
+                $response = DB::query(
+                    "SELECT fonction_id
+                    FROM ".prefix_table("users")."
+                    WHERE login = %s'",
+                    $username
+                );
                 if (count($response) === 0) {
                     rest_error('USER_NOT_EXISTS');
                 }
@@ -392,7 +397,12 @@
                 $folder_arr = array();
                 $roles = explode(";", $role_str);
                 foreach ($roles as $role) {
-                    $response = DB::query("SELECT folder_id FROM ".prefix_table("roles_values")." WHERE role_id='".$role."'");
+                    $response = DB::query(
+                        "SELECT folder_id
+                        FROM ".prefix_table("roles_values")."
+                        WHERE role_id = %i",
+                        $role
+                    );
                     foreach ($response as $data) {
                         $folder_id = $data['folder_id'];
                         if (!array_key_exists($folder_id, $folder_arr)) {
@@ -456,7 +466,12 @@
                 if (strcmp($username, "admin") == 0) {
                     // forbid admin access
                 }
-                $response = DB::query("SELECT fonction_id FROM ".prefix_table("users")." WHERE login='".$username."'");
+                $response = DB::query(
+                    "SELECT fonction_id
+                    FROM ".prefix_table("users")."
+                    WHERE login = %s",
+                    $username
+                );
                 if (count($response) === 0) {
                     rest_error('USER_NOT_EXISTS');
                 }
@@ -468,13 +483,23 @@
                 $roles = explode(";", $role_str);
                 $inc = 0;
                 foreach ($roles as $role) {
-                    $response = DB::query("SELECT folder_id, type FROM ".prefix_table("roles_values")." WHERE role_id='".$role."'");
+                    $response = DB::query(
+                        "SELECT folder_id, type
+                        FROM ".prefix_table("roles_values")."
+                        WHERE role_id = %i",
+                        $role
+                    );
                     foreach ($response as $data) {
                         $folder_id = $data['folder_id'];
                         if (!array_key_exists($folder_id, $folder_arr)) {
                             array_push($folder_arr, $folder_id);
 
-                            $response2 = DB::queryFirstRow("SELECT title, nlevel FROM ".prefix_table("nested_tree")." WHERE id='".$folder_id."'");
+                            $response2 = DB::queryFirstRow(
+                                "SELECT title, nlevel
+                                FROM ".prefix_table("nested_tree")."
+                                WHERE id = %i",
+                                $folder_id
+                            );
 
                             if (!empty($response2['title'])) {
                                 $json[$folder_id]['id'] = $folder_id;
@@ -667,7 +692,13 @@
                     // check if element doesn't already exist
                     $item_duplicate_allowed = getSettingValue("duplicate_item");
                     if ($item_duplicate_allowed !== "1") {
-                        DB::query("SELECT * FROM ".prefix_table("items")." WHERE label = %s AND inactif = %i", addslashes($item_label), "0");
+                        DB::query(
+                            "SELECT *
+                            FROM ".prefix_table("items")."
+                            WHERE label = %s AND inactif = %i",
+                            addslashes($item_label),
+                            "0"
+                        );
                         $counter = DB::count();
                         if ($counter != 0) {
                             $itemExists = 1;
@@ -804,8 +835,9 @@
                 }
                 // Check if user already exists
                 $data = DB::query(
... (diff truncated)
```
