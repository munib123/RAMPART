# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 57_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `57_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 74-114 of the vulnerable file.

        }
    }
}

// type: src, dst
// object_type: (subnets, ipaddresses) - optional
// object_id - optional

# validate type
if($_POST['type']!=="src" && $_POST['type']!=="dst") { $Result->show("danger", _("Invalid type"), true); }

# if type (subnets, ipaddresses) is set and id than just link
if(isset($_POST['object_type']) && isset($_POST['object_id'])) {

    // parameters
    $obj_type = $_POST['object_type'];      // subnets, ipaddresses
    $obj_id   = $_POST['object_id'];        // object identifier
    $nat_id   = $_POST['id'];               // nat id
    $nat_type = $_POST['type'];             // src, dst

    // validate object
    $item = $Tools->fetch_object ($obj_type, "id", $obj_id);
    if($item!==false) {
        // update
        if($nat_type=="src") {
            $nat_array = json_decode($nat->src, true);
        }
        else {
            $nat_array = json_decode($nat->dst, true);
        }

        if(is_array($nat_array[$obj_type]))
        $nat_array[$obj_type] = array_merge($nat_array[$obj_type], array($obj_id));
        else
        $nat_array[$obj_type] = array($obj_id);

        // to json
        if ($nat_type=="src")   { $nat->src = json_encode($nat_array); }
        else                    { $nat->dst = json_encode($nat_array); }

        // update
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,12 @@
     $nat_id   = $_POST['id'];               // nat id
     $nat_type = $_POST['type'];             // src, dst
 
+    // validate object type
+    if (!in_array($obj_type, ['subnets', 'ipaddresses'])) { $Result->show("danger", _("Invalid object type"), true); }
+
+    // validate object id
+    if (!is_numeric($obj_id)) { $Result->show("danger", _("Invalid object id"), true); }
+
     // validate object
     $item = $Tools->fetch_object ($obj_type, "id", $obj_id);
     if($item!==false) {
```
