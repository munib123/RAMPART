# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 1088_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1088_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 318-358 of the vulnerable file.

                    'admin_edit' => array('perm_regexp_access'),
                    'admin_index' => array('perm_regexp_access'),
                    'cleanRegexModifiers' => array('perm_regexp_access'),
                    'index' => array('*'),
            ),
            'restClientHistory' => array(
                    'delete' => array('*'),
                    'index' => array('*')
            ),
            'roles' => array(
                    'admin_add' => array(),
                    'admin_delete' => array(),
                    'admin_edit' => array(),
                    'admin_index' => array('perm_admin'),
                    'admin_set_default' => array(),
                    'index' => array('*'),
                    'view' => array('*'),
            ),
            'servers' => array(
                    'add' => array(),
                    'cache' => array('perm_site_admin'),
                    'checkout' => array(),
                    'createSync' => array('perm_sync'),
                    'delete' => array(),
                    'deleteFile' => array(),
                    'edit' => array(),
                    'fetchServersForSG' => array('*'),
                    'filterEventIndex' => array(),
                    'getApiInfo' => array('*'),
                    'getGit' => array(),
                    'getInstanceUUID' => array('perm_sync'),
                    'getPyMISPVersion' => array('*'),
                    'getSetting' => array(),
                    'getSubmodulesStatus' => array('perm_site_admin'),
                    'getSubmoduleQuickUpdateForm' => array('perm_site_admin'),
                    'getWorkers' => array(),
                    'getVersion' => array('*'),
                    'import' => ('perm_site_admin'),
                    'index' => array('OR' => array('perm_sync', 'perm_admin')),
                    'ondemandAction' => array(),
                    'postTest' => array('perm_sync'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -335,7 +335,7 @@
             ),
             'servers' => array(
                     'add' => array(),
-                    'cache' => array('perm_site_admin'),
+                    'cache' => array(),
                     'checkout' => array(),
                     'createSync' => array('perm_sync'),
                     'delete' => array(),
@@ -348,14 +348,14 @@
                     'getInstanceUUID' => array('perm_sync'),
                     'getPyMISPVersion' => array('*'),
                     'getSetting' => array(),
-                    'getSubmodulesStatus' => array('perm_site_admin'),
-                    'getSubmoduleQuickUpdateForm' => array('perm_site_admin'),
+                    'getSubmodulesStatus' => array(),
+                    'getSubmoduleQuickUpdateForm' => array(),
                     'getWorkers' => array(),
                     'getVersion' => array('*'),
-                    'import' => ('perm_site_admin'),
-                    'index' => array('OR' => array('perm_sync', 'perm_admin')),
+                    'import' => array(),
+                    'index' => array(),
                     'ondemandAction' => array(),
-                    'postTest' => array('perm_sync'),
+                    'postTest' => array(),
                     'previewEvent' => array(),
                     'previewIndex' => array(),
                     'pull' => array(),
@@ -371,7 +371,7 @@
                     'statusZeroMQServer' => array(),
                     'stopWorker' => array(),
                     'stopZeroMQServer' => array(),
-                    'testConnection' => array('perm_sync'),
+                    'testConnection' => array(),
                     'update' => array(),
                     'updateJSON' => array(),
                     'updateProgress' => array(),
@@ -518,6 +518,7 @@
                     'initiatePasswordReset' => array('perm_admin'),
                     'login' => array('*'),
                     'logout' => array('*'),
+                    'resetAllSyncAuthKeys' => array(),
                     'resetauthkey' => array('*'),
                     'request_API' => array('*'),
                     'routeafterlogin' => array('*'),
@@ -552,6 +553,78 @@
                     'delete' => array('perm_modify'),
             )
     );
+
+    private function __checkLoggedActions($user, $controller, $action)
+    {
+        $loggedActions = array(
+            'servers' => array(
+                'index' => array(
+                    'role' => array(
+                        'NOT' => array(
+                            'perm_site_admin'
+                        )
+                    ),
+                    'message' => __('This could be an indication of an attempted privilege escalation on older vulnerable versions of MISP (<2.4.115)')
+                )
+            )
+        );
+        foreach ($loggedActions as $k => $v) {
+            $loggedActions[$k] = array_change_key_case($v);
+        }
+        $message = '';
+        if (!empty($loggedActions[$controller])) {
+            if (!empty($loggedActions[$controller][$action])) {
+                $message = $loggedActions[$controller][$action]['message'];
+                $hit = false;
+                if (empty($loggedActions[$controller][$action]['role'])) {
+                    $hit = true;
+                } else {
+                    $role_req = $loggedActions[$controller][$action]['role'];
+                    if (empty($role_req['OR']) && empty($role_req['AND']) && empty($role_req['NOT'])) {
+                        $role_req = array('OR' => $role_req);
+                    }
+                    if (!empty($role_req['NOT'])) {
+                        foreach ($role_req['NOT'] as $k => $v) {
+                            if (!$user['Role'][$v]) {
+                                $hit = true;
+                                continue;
+                            }
+                        }
+                    }
+                    if (!$hit && !empty($role_req['AND'])) {
+                        $subhit = true;
+                        foreach ($role_req['AND'] as $k => $v) {
+                            $subhit = $subhit && $user['Role'][$v];
+                        }
+                        if ($subhit) {
+                            $hit = true;
+                        }
+                    }
+                    if (!$hit && !empty($role_req['OR'])) {
+                        foreach ($role_req['OR'] as $k => $v) {
+                            if ($user['Role'][$v]) {
+                                $hit = true;
+                                continue;
+                            }
+                        }
+                    }
+                    if ($hit) {
+                        $this->Log = ClassRegistry::init('Log');
+                        $this->Log->create();
+                        $this->Log->save(array(
+                                'org' => 'SYSTEM',
+                                'model' => 'User',
+                                'model_id' => $user['id'],
+                                'email' => $user['email'],
+                                'action' => 'security',
+                                'user_id' => $user['id'],
+                                'title' => __('User triggered security alert by attempting to access /%s/%s. Reason why this endpoint is of interest: %s', $controller, $action, $message),
+                        ));
+                    }
+                }
+            }
+        }
+    }
 
     // The check works like this:
     // If the user is a site admin, return true
@@ -567,6 +640,7 @@
         foreach ($aclList as $k => $v) {
             $aclList[$k] = array_change_key_case($v);
         }
+        $this->__checkLoggedActions($user, $controller, $action);
         if ($user['Role']['perm_site_admin']) {
             return true;
         }
```
