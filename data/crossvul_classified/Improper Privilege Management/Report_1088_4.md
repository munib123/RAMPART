# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 1088_4
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1088_4`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

                            'edit',
                            'email',
                            'enable',
                            'error',
                            'export',
                            'file_upload',
                            'galaxy',
                            'login',
                            'login_fail',
                            'logout',
                            'merge',
                            'pruneUpdateLogs',
                            'publish',
                            'publish alert',
                            'pull',
                            'push',
                            'remove_dead_workers',
                            'request',
                            'request_delegation',
                            'reset_auth_key',
                            'serverSettingsEdit',
                            'tag',
                            'undelete',
                            'update',
                            'update_database',
                            'upgrade_24',
                            'upload_sample',
                            'version_warning',
                            'warning'
                        )),
            'message' => 'Options : ...'
        )
    );

    public $actionDefinitions = array(
        'login' => array('desc' => 'Login action', 'formdesc' => "Login action"),
        'logout' => array('desc' => 'Logout action', 'formdesc' => "Logout action"),
        'add' => array('desc' => 'Add action', 'formdesc' => "Add action"),
        'edit' => array('desc' => 'Edit action', 'formdesc' => "Edit action"),
        'change_pw' => array('desc' => 'Change_pw action', 'formdesc' => "Change_pw action"),
        'delete' => array('desc' => 'Delete action', 'formdesc' => "Delete action"),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
                             'request',
                             'request_delegation',
                             'reset_auth_key',
+                            'security',
                             'serverSettingsEdit',
                             'tag',
                             'undelete',
```
