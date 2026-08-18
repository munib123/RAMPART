# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 1088_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1088_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 489-509 of the vulnerable file.

            $this->loadModel('AdminSetting');
            $db_version = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'db_version')));
            if (!empty($db_version)) {
                $db_version['AdminSetting']['value'] = $last_db_num;
                $this->AdminSetting->save($db_version);
                $this->Server->runUpdates(true);
            } else {
                echo __('Something went wrong. Could not find the existing db version') . PHP_EOL;
            }
        } else {
            echo __('DB was never successfully updated or we are on a fresh install') . PHP_EOL;
        }
    }

    public function cleanCaches()
    {
        echo 'Cleaning caches...' . PHP_EOL;
        $this->Server->cleanCacheFiles();
        echo '...caches lost in time, like tears in rain.' . PHP_EOL;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -506,4 +506,30 @@
         $this->Server->cleanCacheFiles();
         echo '...caches lost in time, like tears in rain.' . PHP_EOL;
     }
+
+    public function resetSyncAuthkeys()
+    {
+        if (empty($this->args[0])) {
+            echo sprintf(
+                __("MISP mass sync authkey reset command line tool.\n\nUsage: %sConsole/cake resetSyncAuthkeys [user_id]") . "\n\n",
+                APP
+            );
+            die();
+        } else {
+            $userId = $this->args[0];
+            $user = $this->User->getAuthUser($userId);
+            if (empty($user)) {
+                echo __('Invalid user.') . "\n\n";
+            }
+            if (!$user['Role']['perm_site_admin']) {
+                echo __('User has to be a site admin.') . "\n\n";
+            }
+            if (!empty($this->args[1])) {
+                $jobId = $this->args[1];
+            } else {
+                $jobId = false;
+            }
+            $this->User->resetAllSyncAuthKeys($user, $jobId);
+        }
+    }
 }
```
