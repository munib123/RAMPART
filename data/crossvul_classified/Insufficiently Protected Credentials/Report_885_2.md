# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 885_2
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `885_2`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 278-298 of the vulnerable file.

            // write to syslogd as well
            $syslog = new SysLog();
            $action = 'info';
            if (isset($data['Log']['action'])) {
                if (in_array($data['Log']['action'], $this->errorActions)) {
                    $action = 'err';
                }
                if (in_array($data['Log']['action'], $this->warningActions)) {
                    $action = 'warning';
                }
            }

            $entry = $data['Log']['action'];
            if (!empty($data['Log']['description'])) {
                $entry .= sprintf(' -- %s', $data['Log']['description']);
            }
            $syslog->write($action, $entry);
        }
        return true;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,4 +295,31 @@
         }
         return true;
     }
+
+    public function filterSiteAdminSensitiveLogs($list)
+    {
+        $this->User = ClassRegistry::init('User');
+        $site_admin_roles = $this->User->Role->find('list', array(
+            'recursive' => -1,
+            'conditions' => array('Role.perm_site_admin' => 1),
+            'fields' => array('Role.id', 'Role.id')
+        ));
+        $site_admins = $this->User->find('list', array(
+            'recursive' => -1,
+            'conditions' => array(
+                'User.role_id' => array_values($site_admin_roles)
+            ),
+            'fields' => array('User.id', 'User.id')
+        ));
+        foreach ($list as $k => $v) {
+            if (
+                $v['Log']['model'] === 'User' &&
+                in_array($v['Log']['model_id'], array_values($site_admins)) &&
+                in_array($v['Log']['action'], array('add', 'edit', 'reset_auth_key'))
+            ) {
+                $list[$k]['Log']['change'] = __('Redacted');
+            }
+        }
+        return $list;
+    }
 }
```
