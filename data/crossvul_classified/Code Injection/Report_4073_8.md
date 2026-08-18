# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4073_8
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_8`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

    echo json_encode($response);
}

if ($_POST['action'] == 'get_groups') {
    // List all available groups
    try {
        $query = $db->query('SELECT * FROM "group";');
        $data = array();
        while (($res = $query->fetchArray(SQLITE3_ASSOC)) !== false) {
            array_push($data, $res);
        }

        header('Content-type: application/json');
        echo json_encode(array('data' => $data));
    } catch (\Exception $ex) {
        JSON_error($ex->getMessage());
    }
} elseif ($_POST['action'] == 'add_group') {
    // Add new group
    try {
        $names = str_getcsv(trim($_POST['name']), ' ');
        $total = count($names);
        $added = 0;
        $stmt = $db->prepare('INSERT INTO "group" (name,description) VALUES (:name,:desc)');
        if (!$stmt) {
            throw new Exception('While preparing statement: ' . $db->lastErrorMsg());
        }

        $desc = $_POST['desc'];
        if (strlen($desc) === 0) {
            // Store NULL in database for empty descriptions
            $desc = null;
        }
        if (!$stmt->bindValue(':desc', $desc, SQLITE3_TEXT)) {
            throw new Exception('While binding desc: ' . $db->lastErrorMsg());
        }

        foreach ($names as $name) {
            if (!$stmt->bindValue(':name', $name, SQLITE3_TEXT)) {
                throw new Exception('While binding name: <strong>' . $db->lastErrorMsg() . '</strong><br>'.
                'Added ' . $added . " out of ". $total . " groups");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,8 @@
 } elseif ($_POST['action'] == 'add_group') {
     // Add new group
     try {
-        $names = str_getcsv(trim($_POST['name']), ' ');
+        $input = html_entity_decode(trim($_POST['name']));
+        $names = str_getcsv($input, ' ');
         $total = count($names);
         $added = 0;
         $stmt = $db->prepare('INSERT INTO "group" (name,description) VALUES (:name,:desc)');
@@ -96,6 +97,9 @@
 } elseif ($_POST['action'] == 'edit_group') {
     // Edit group identified by ID
     try {
+        $name = html_entity_decode($_POST['name']);
+        $desc = html_entity_decode($_POST['desc']);
+
         $stmt = $db->prepare('UPDATE "group" SET enabled=:enabled, name=:name, description=:desc WHERE id = :id');
         if (!$stmt) {
             throw new Exception('While preparing statement: ' . $db->lastErrorMsg());
@@ -106,11 +110,10 @@
             throw new Exception('While binding enabled: ' . $db->lastErrorMsg());
         }
 
-        if (!$stmt->bindValue(':name', $_POST['name'], SQLITE3_TEXT)) {
+        if (!$stmt->bindValue(':name', $name, SQLITE3_TEXT)) {
             throw new Exception('While binding name: ' . $db->lastErrorMsg());
         }
 
-        $desc = $_POST['desc'];
         if (strlen($desc) === 0) {
             // Store NULL in database for empty descriptions
             $desc = null;
@@ -263,7 +266,7 @@
                 throw new Exception('While binding ip: ' . $db->lastErrorMsg());
             }
 
-            $comment = $_POST['comment'];
+            $comment = html_entity_decode($_POST['comment']);
             if (strlen($comment) === 0) {
                     // Store NULL in database for empty comments
                     $comment = null;
@@ -293,7 +296,7 @@
             throw new Exception('While preparing statement: ' . $db->lastErrorMsg());
         }
 
-        $comment = $_POST['comment'];
+        $comment = html_entity_decode($_POST['comment']);
         if (strlen($comment) === 0) {
                 // Store NULL in database for empty comments
                 $comment = null;
@@ -453,7 +456,7 @@
 } elseif ($_POST['action'] == 'add_domain') {
     // Add new domain
     try {
-        $domains = explode(' ', trim($_POST['domain']));
+        $domains = explode(' ', html_entity_decode(trim($_POST['domain'])));
         $before = intval($db->querySingle("SELECT COUNT(*) FROM domainlist;"));
         $total = count($domains);
         $added = 0;
@@ -474,7 +477,7 @@
             throw new Exception('While binding type: ' . $db->lastErrorMsg());
         }
 
-        $comment = $_POST['comment'];
+        $comment = html_entity_decode($_POST['comment']);
         if (strlen($comment) === 0) {
             // Store NULL in database for empty comments
             $comment = null;
@@ -573,7 +576,7 @@
             throw new Exception('While binding enabled: ' . $db->lastErrorMsg());
         }
 
-        $comment = $_POST['comment'];
+        $comment = html_entity_decode($_POST['comment']);
         if (strlen($comment) === 0) {
                 // Store NULL in database for empty comments
                 $comment = null;
@@ -742,7 +745,7 @@
 } elseif ($_POST['action'] == 'add_adlist') {
     // Add new adlist
     try {
-        $addresses = explode(' ', trim($_POST['address']));
+        $addresses = explode(' ', html_entity_decode(trim($_POST['address'])));
         $total = count($addresses);
         $added = 0;
 
@@ -751,7 +754,7 @@
             throw new Exception('While preparing statement: ' . $db->lastErrorMsg());
         }
 
-        $comment = $_POST['comment'];
+        $comment = html_entity_decode($_POST['comment']);
         if (strlen($comment) === 0) {
             // Store NULL in database for empty comments
             $comment = null;
@@ -800,7 +803,7 @@
             throw new Exception('While binding enabled: ' . $db->lastErrorMsg());
         }
 
-        $comment = $_POST['comment'];
+        $comment = html_entity_decode($_POST['comment']);
         if (strlen($comment) === 0) {
                 // Store NULL in database for empty comments
                 $comment = null;
```
