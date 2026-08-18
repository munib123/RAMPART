# CrossVul Fix Pair: Time-of-check Time-of-use (TOCTOU) Race Condition in php
**Pair ID:** 4662_0
**Vulnerability Class:** Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4662_0`)

## Vulnerability Information & PoC

## Description
Time-of-check Time-of-use (TOCTOU) Race Condition - This weakness can be security-relevant when an attacker can influence the state of the resource between check and use.

## Vulnerable Code
```php
Lines 32-62 of the vulnerable file.

        $this->Log->save($log);
    }

    public function clean()
    {
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        $dataSource = $dataSourceConfig['datasource'];
        if ($dataSource == 'Database/Mysql') {
            $sql = 'DELETE FROM bruteforces WHERE `expire` <= NOW();';
        } elseif ($dataSource == 'Database/Postgres') {
            $sql = 'DELETE FROM bruteforces WHERE expire <= NOW();';
        }
        $this->query($sql);
    }

    public function isBlacklisted($ip, $username)
    {
        // first remove old expired rows
        $this->clean();
        // count
        $params = array('conditions' => array(
                        'Bruteforce.ip' => $ip,
                        'Bruteforce.username' => $username),);
        $count = $this->find('count', $params);
        if ($count >= Configure::read('SecureAuth.amount')) {
            return true;
        } else {
            return false;
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,11 +49,14 @@
         // first remove old expired rows
         $this->clean();
         // count
-        $params = array('conditions' => array(
-                        'Bruteforce.ip' => $ip,
-                        'Bruteforce.username' => $username),);
+        $params = array(
+            'conditions' => array(
+            'Bruteforce.ip' => $ip,
+            'LOWER(Bruteforce.username)' => trim(strtolower($username)))
+        );
         $count = $this->find('count', $params);
-        if ($count >= Configure::read('SecureAuth.amount')) {
+        $amount = Configure::check('SecureAuth.amount') ? Configure::read('SecureAuth.amount') : 5;
+        if ($count >= $amount) {
             return true;
         } else {
             return false;
```
