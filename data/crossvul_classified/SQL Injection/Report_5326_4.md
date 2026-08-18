# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5326_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5326_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 235-275 of the vulnerable file.

            $path = str_replace(BASE, '', $this->params['id']);
            $path = str_replace('\\', '/', $path);
            $file = $efile->find('first','directory="'.dirname($path).'/'.'" AND filename="'.basename($path).'"');
        }
        $ar = new expAjaxReply(200, 'ok', $file);
        $ar->send();
    }

    public function getFilesByJSON() {
        global $user;

        $modelname = $this->basemodel_name;
        $results = 25; // default get all
        $startIndex = 0; // default start at 0
//        $sort = null; // default don't sort
//        $dir = 'asc'; // default sort dir is asc
//        $sort_dir = SORT_ASC;

        // How many records to get?
        if(strlen($this->params['results']) > 0) {
            $results = $this->params['results'];
        }

        // Start at which record?
        if(strlen($this->params['startIndex']) > 0) {
            $startIndex = $this->params['startIndex'];
        }

        // Sorted?
        if(strlen($this->params['sort']) > 0) {
            if ($this->params['sort'] == 'cat') {
                $sort = 'id';
            } else {
                $sort = $this->params['sort'];
            }
//            if ($sort = 'id') $sort = 'filename';
        }

        // Sort dir?
        if (($this->params['dir'] == 'false') || ($this->params['dir'] == 'desc') || ($this->params['dir'] == 'yui-dt-desc')) {
            $dir = 'desc';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,12 +252,12 @@
 
         // How many records to get?
         if(strlen($this->params['results']) > 0) {
-            $results = $this->params['results'];
+            $results = intval($this->params['results']);
         }
 
         // Start at which record?
         if(strlen($this->params['startIndex']) > 0) {
-            $startIndex = $this->params['startIndex'];
+            $startIndex = intval($this->params['startIndex']);
         }
 
         // Sorted?
@@ -265,7 +265,7 @@
             if ($this->params['sort'] == 'cat') {
                 $sort = 'id';
             } else {
-                $sort = $this->params['sort'];
+                $sort = expString::escape($this->params['sort']);
             }
 //            if ($sort = 'id') $sort = 'filename';
         }
@@ -281,6 +281,7 @@
         $totalrecords = 0;
 
         if (!empty($this->params['query'])) {
+            $this->params['query'] = expString::escape($this->params['query']);
             $filter = '';
             if (!$user->isAdmin()) {
                 $filter = "(poster=".$user->id." OR shared=1) AND ";
```
