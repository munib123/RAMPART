# CrossVul Fix Pair: Origin Validation Error in php
**Pair ID:** 4368_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4368_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```php
Lines 476-522 of the vulnerable file.

      $type = 'Kirby 2 Personal';
    } else if(str::startsWith($key, 'MD-') and str::length($key) == 35) {
      $type = 'Kirby 1';
    } else if(str::startsWith($key, 'BETA') and str::length($key) == 9) {
      $type = 'Kirby 1';
    } else if(str::length($key) == 32) {
      $type = 'Kirby 1';
    } else {
      $key = null;
    }

    return new Obj(array(
      'key'   => $key,
      'local' => $this->isLocal(),
      'type'  => $type,
    ));

  }

  public function isLocal() {
    $localhosts = array('::1', '127.0.0.1', '0.0.0.0');
    return (
      in_array(server::get('SERVER_ADDR'), $localhosts) ||
      server::get('SERVER_NAME') == 'localhost' ||
      str::endsWith(server::get('SERVER_NAME'), '.localhost') ||
      str::endsWith(server::get('SERVER_NAME'), '.test')
    );
  }

  public function notify($text) {
    s::set('kirby_panel_message', array(
      'type' => 'notification',
      'text' => $text,
    ));
  }

  public function alert($text) {
    s::set('kirby_panel_message', array(
      'type' => 'error',
      'text' => $text,
    ));
  }

  public function redirect($obj = '/', $action = false, $force = false) {

    if($force === false and $redirect = get('_redirect')) {
      $url = purl($redirect);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -493,13 +493,47 @@
   }
 
   public function isLocal() {
-    $localhosts = array('::1', '127.0.0.1', '0.0.0.0');
-    return (
-      in_array(server::get('SERVER_ADDR'), $localhosts) ||
-      server::get('SERVER_NAME') == 'localhost' ||
-      str::endsWith(server::get('SERVER_NAME'), '.localhost') ||
-      str::endsWith(server::get('SERVER_NAME'), '.test')
-    );
+
+    $host = server::get('SERVER_NAME');
+    $ip   = server::get('SERVER_ADDR');
+
+    if ($host === 'localhost') {
+      return true;
+    }
+
+    if (str::endsWith($host, '.localhost') === true) {
+      return true;
+    }
+
+    if (str::endsWith($host, '.local') === true) {
+      return true;
+    }
+
+    if (str::endsWith($host, '.test') === true) {
+      return true;
+    }
+
+    if (in_array($ip, ['::1', '127.0.0.1']) === true) {
+
+      if (
+        isset($_SERVER['HTTP_X_FORWARDED_FOR']) === true &&
+        in_array($_SERVER['HTTP_X_FORWARDED_FOR'], ['::1', '127.0.0.1']) === false
+      ) {
+        return false;
+      }
+
+      if (
+        isset($_SERVER['HTTP_CLIENT_IP']) === true &&
+        in_array($_SERVER['HTTP_CLIENT_IP'], ['::1', '127.0.0.1']) === false
+      ) {
+        return false;
+      }
+
+      // no reverse proxy or the real client also comes from localhost
+      return true;
+    }
+
+    return false;
   }
 
   public function notify($text) {
```
