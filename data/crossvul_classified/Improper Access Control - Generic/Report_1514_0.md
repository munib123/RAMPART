# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 1514_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1514_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-30 of the vulnerable file.

<?php

class remote_plugin_acl extends DokuWiki_Remote_Plugin {
    function _getMethods() {
        return array(
            'addAcl' => array(
                'args' => array('string','string','int'),
                'return' => 'int',
                'name' => 'addAcl',
                'doc' => 'Adds a new ACL rule.'
            ), 'delAcl' => array(
                'args' => array('string','string'),
                'return' => 'int',
                'name' => 'delAcl',
                'doc' => 'Delete an existing ACL rule.'
            ),
        );
    }

    function addAcl($scope, $user, $level){
        $apa = plugin_load('admin', 'acl');
        return $apa->_acl_add($scope, $user, $level);
    }

    function delAcl($scope, $user){
        $apa = plugin_load('admin', 'acl');
        return $apa->_acl_del($scope, $user);
    }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,12 +17,39 @@
         );
     }
 
-    function addAcl($scope, $user, $level){
+    /**
+     * Add a new entry to ACL config
+     *
+     * @param string $scope
+     * @param string $user
+     * @param int    $level see also inc/auth.php
+     * @throws RemoteAccessDeniedException
+     * @return bool
+     */
+    public function addAcl($scope, $user, $level){
+        if(!auth_isadmin()) {
+            throw new RemoteAccessDeniedException('You are not allowed to access ACLs, superuser permission is required', 114);
+        }
+
+        /** @var admin_plugin_acl $apa */
         $apa = plugin_load('admin', 'acl');
         return $apa->_acl_add($scope, $user, $level);
     }
 
-    function delAcl($scope, $user){
+    /**
+     * Remove an entry from ACL config
+     *
+     * @param string $scope
+     * @param string $user
+     * @throws RemoteAccessDeniedException
+     * @return bool
+     */
+    public function delAcl($scope, $user){
+        if(!auth_isadmin()) {
+            throw new RemoteAccessDeniedException('You are not allowed to access ACLs, superuser permission is required', 114);
+        }
+
+        /** @var admin_plugin_acl $apa */
         $apa = plugin_load('admin', 'acl');
         return $apa->_acl_del($scope, $user);
     }
```
