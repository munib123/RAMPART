# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5406_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5406_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

    );

    static function displayname() {
        return gt("User Manager");
    }

    static function description() {
        return gt("This is the user management module. It allows for creating user, editing user, etc.");
    }

    static function hasSources() {
        return false;
    }

    static function hasContent() {
        return false;
    }

    static function canImportData() {
        return true;
    }

    public function manage() {
        global $user;

        expHistory::set('manageable', $this->params);
//        $limit = empty($this->config['limit']) ? 10 : $this->config['limit'];
//        $order = empty($this->config['order']) ? 'username' : $this->config['order'];
        if ($user->is_system_user == 1) {
//            $filter = 1; //'1';
            $where = '';
        } elseif ($user->isSuperAdmin()) {
//            $filter = 2; //"is_system_user != 1";
            $where = "is_system_user != 1";
        } else {
//            $filter = 3; //"is_admin != 1";
            $where = "is_admin != 1";
        }
        $page = new expPaginator(array(
                    'model'=>'user',
                    'where'=>$where,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,25 @@
 
     static function canImportData() {
         return true;
+    }
+
+    public function show() {
+        global $user;
+
+        $id = !empty($this->params['id']) ? $this->params['id'] : null;
+
+        // check to see if we should be editing.  You either need to be an admin, or viewing own account.
+        if ($user->isAdmin() || ($user->id == $id)) {
+            $u = new user($id);
+            if ($u->isSuperAdmin() && $user->isActingAdmin()) {
+                flash('error', gt('You do not have the proper permissions to view this record'));
+                expHistory::back();
+            }
+            parent::show();
+        } else {
+            flash('error', gt('You do not have the proper permissions to view this record'));
+            expHistory::back();
+        }
     }
 
     public function manage() {
```
