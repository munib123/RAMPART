# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1634_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1634_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1567-1607 of the vulnerable file.


        if ($asset = Asset::getById($this->getParam("id"))) {
            if (method_exists($asset, "clearThumbnails")) {
                $asset->clearThumbnails(true); // force clear
                $asset->save();

                $success = true;
            }
        }

        $this->_helper->json(array("success" => $success));
    }

    public function gridProxyAction() {

        if ($this->getParam("data")) {
            if ($this->getParam("xaction") == "update") {
                //TODO probably not needed
            }
        } else {
            // get list of objects
            $folder = Asset::getById($this->getParam("folderId"));


            $start = 0;
            $limit = 20;
            $orderKey = "id";
            $order = "ASC";


            if ($this->getParam("limit")) {
                $limit = $this->getParam("limit");
            }
            if ($this->getParam("start")) {
                $start = $this->getParam("start");
            }

            if ($this->getParam("dir")) {
                $order = $this->getParam("dir");
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1584,7 +1584,8 @@
                 //TODO probably not needed
             }
         } else {
-            // get list of objects
+            $db = \Pimcore\Resource::get();
+                // get list of objects
             $folder = Asset::getById($this->getParam("folderId"));
 
 
@@ -1665,7 +1666,7 @@
                         $field = "CONCAT(path,filename)";
                     }
 
-                    $conditionFilters[] =  $field . $operator . " '" . $value . "' ";
+                    $conditionFilters[] =  $field . $operator . " " . $db->quote($value);
                 }
             }
 
```
