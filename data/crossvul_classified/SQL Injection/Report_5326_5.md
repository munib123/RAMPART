# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5326_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5326_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 825-865 of the vulnerable file.

            foreach ($this->params['memdata'] as $u => $str) {
                $memb->member_id = $u;
                $memb->is_admin = $str['is_admin'];
                $db->insertObject($memb, 'groupmembership');
            }
        }
        expSession::triggerRefresh();
        expHistory::back();
    }

    public function getUsersByJSON() {
        $modelname = $this->basemodel_name;
        $results = 25; // default get 25
        $startIndex = 0; // default start at 0
        $sort = null; // default don't sort
        $dir = 'asc'; // default sort dir is asc
        $sort_dir = SORT_ASC;

        // How many records to get?
        if (strlen($this->params['results']) > 0) {
            $results = $this->params['results'];
        }

        // Start at which record?
        if (strlen($this->params['startIndex']) > 0) {
            $startIndex = $this->params['startIndex'];
        }

        // Sorted?
        if (strlen($this->params['sort']) > 0) {
            $sort = $this->params['sort'];
            if ($sort = 'id') $sort = 'username';
        }

        if (!empty($this->params['filter'])) {
            switch ($this->params['filter']) {
                case '1' :
                    $filter = '';
                    break;
                case '2' :
                    $filter = "is_system_user != 1";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -842,17 +842,17 @@
 
         // How many records to get?
         if (strlen($this->params['results']) > 0) {
-            $results = $this->params['results'];
+            $results = intval($this->params['results']);
         }
 
         // Start at which record?
         if (strlen($this->params['startIndex']) > 0) {
-            $startIndex = $this->params['startIndex'];
+            $startIndex = intval($this->params['startIndex']);
         }
 
         // Sorted?
         if (strlen($this->params['sort']) > 0) {
-            $sort = $this->params['sort'];
+            $sort = expString::escape($this->params['sort']);
             if ($sort = 'id') $sort = 'username';
         }
 
@@ -893,11 +893,10 @@
 
         if (!empty($this->params['query'])) {
 
-//            $this->params['query'] = $this->params['query'];
+            $this->params['query'] = expString::escape($this->params['query']);
             $totalrecords = $this->$modelname->find('count', (empty($filter) ? '' : $filter . " AND ") . "(username LIKE '%" . $this->params['query'] . "%' OR firstname LIKE '%" . $this->params['query'] . "%' OR lastname LIKE '%" . $this->params['query'] . "%' OR email LIKE '%" . $this->params['query'] . "%')");
 
             $users = $this->$modelname->find('all', (empty($filter) ? '' : $filter . " AND ") . "(username LIKE '%" . $this->params['query'] . "%' OR firstname LIKE '%" . $this->params['query'] . "%' OR lastname LIKE '%" . $this->params['query'] . "%' OR email LIKE '%" . $this->params['query'] . "%')", $sort . ' ' . $dir, $results, $startIndex);
-
             for ($i = 0, $iMax = count($users); $i < $iMax; $i++) {
                 if (ECOM == 1) {
                     $users[$i]->usernamelabel = "<a href='viewuser/{$users[$i]->id}'  class='fileinfo'>{$users[$i]->username}</a>";
```
