# CrossVul Fix Pair: Time-of-check Time-of-use (TOCTOU) Race Condition in php
**Pair ID:** 4661_1
**Vulnerability Class:** Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4661_1`)

## Vulnerability Information & PoC

## Description
Time-of-check Time-of-use (TOCTOU) Race Condition - This weakness can be security-relevant when an attacker can influence the state of the resource between check and use.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class Bruteforce extends AppModel
{
    public function insert($ip, $username)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $expire = time() + Configure::read('SecureAuth.expire');
        $expire = date('Y-m-d H:i:s', $expire);
        $bruteforceEntry = array(
            'ip' => $ip,
            'username' => $username,
            'expire' => $expire
        );
        $this->save($bruteforceEntry);
        $title = 'Failed login attempt using username ' . $username . ' from IP: ' . $_SERVER['REMOTE_ADDR'] . '.';
        if ($this->isBlacklisted($ip, $username)) {
            $title .= 'This has tripped the bruteforce protection after  ' . Configure::read('SecureAuth.amount') . ' failed attempts. The user is now blacklisted for ' . Configure::read('SecureAuth.expire') . ' seconds.';
        }
        $log = array(
                'org' => 'SYSTEM',
                'model' => 'User',
                'model_id' => 0,
                'email' => $username,
                'action' => 'login_fail',
                'title' => $title
        );
        $this->Log->save($log);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,17 +9,19 @@
     {
         $this->Log = ClassRegistry::init('Log');
         $this->Log->create();
-        $expire = time() + Configure::read('SecureAuth.expire');
+        $expire = Configure::check('SecureAuth.expire') ? Configure::read('SecureAuth.expire') : 300;
+        $amount = Configure::check('SecureAuth.amount') ? Configure::read('SecureAuth.amount') : 5;
+        $expire = time() + $expire;
         $expire = date('Y-m-d H:i:s', $expire);
         $bruteforceEntry = array(
             'ip' => $ip,
-            'username' => $username,
+            'username' => trim(strtolower($username)),
             'expire' => $expire
         );
         $this->save($bruteforceEntry);
         $title = 'Failed login attempt using username ' . $username . ' from IP: ' . $_SERVER['REMOTE_ADDR'] . '.';
         if ($this->isBlacklisted($ip, $username)) {
-            $title .= 'This has tripped the bruteforce protection after  ' . Configure::read('SecureAuth.amount') . ' failed attempts. The user is now blacklisted for ' . Configure::read('SecureAuth.expire') . ' seconds.';
+            $title .= 'This has tripped the bruteforce protection after  ' . $amount . ' failed attempts. The user is now blacklisted for ' . $expire . ' seconds.';
         }
         $log = array(
                 'org' => 'SYSTEM',
@@ -36,10 +38,11 @@
     {
         $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
         $dataSource = $dataSourceConfig['datasource'];
+        $expire = date('Y-m-d H:i:s', time());
         if ($dataSource == 'Database/Mysql') {
-            $sql = 'DELETE FROM bruteforces WHERE `expire` <= NOW();';
+            $sql = 'DELETE FROM bruteforces WHERE `expire` <= "' . $expire . '";';
         } elseif ($dataSource == 'Database/Postgres') {
-            $sql = 'DELETE FROM bruteforces WHERE expire <= NOW();';
+            $sql = 'DELETE FROM bruteforces WHERE expire <= "' . $expire . '";';
         }
         $this->query($sql);
     }
```
