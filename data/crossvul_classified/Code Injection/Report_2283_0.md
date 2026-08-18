# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 2283_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2283_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 36-77 of the vulnerable file.

    $extension = '';
    $displayname = '';
    $vm_password = '';
    $category = '';
    $context = '';
    $voicemail_enabled = '';
    $voicemail_email_address = '';
    $voicemail_pager_address = '';
    $voicemail_email_enable = '';
    $admin = '';
    $admin_callmonitor = '';
    $default_page = '';

    $username = '';
    $password = '';

    // get the ari authentication cookie 
    $data = '';
    $chksum = '';
    if (isset($_COOKIE['ari_auth'])) {
      $buf = unserialize(stripslashes($_COOKIE['ari_auth']));
      list($data,$chksum) = $buf;
    }
    if (md5($data) == $chksum) {
      $data = unserialize($crypt->decrypt($data,$ARI_CRYPT_PASSWORD));
      $username = $data['username'];
      $password = $data['password'];
    }

    if (isset($_POST['username']) && 
          isset($_POST['password'])) {
      $username = $_POST['username'];
      $password = $_POST['password'];
    }

    // init email options array
    $voicemail_email = array();

    // when login, make a new session
    if ($username && !$ARI_NO_LOGIN) {

      $auth = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,11 +53,16 @@
     $data = '';
     $chksum = '';
     if (isset($_COOKIE['ari_auth'])) {
-      $buf = unserialize(stripslashes($_COOKIE['ari_auth']));
-      list($data,$chksum) = $buf;
+      $buf = json_decode($_COOKIE['ari_auth'],true);
+      if(!is_array($buf)) {
+        $data = false;
+        $chksum = false;
+      } else {
+        list($data,$chksum) = $buf;
+      }
     }
     if (md5($data) == $chksum) {
-      $data = unserialize($crypt->decrypt($data,$ARI_CRYPT_PASSWORD));
+      $data = json_decode($crypt->decrypt($data,$ARI_CRYPT_PASSWORD),true);
       $username = $data['username'];
       $password = $data['password'];
     }
@@ -290,11 +295,11 @@
       if ($auth && $remember) {
 
         $data = array('username' => $username, 'password' => $password);
-        $data = $crypt->encrypt(serialize($data),$ARI_CRYPT_PASSWORD);
+        $data = $crypt->encrypt(json_encode($data),$ARI_CRYPT_PASSWORD);
 
         $chksum = md5($data);
 
-        $buf = serialize(array($data,$chksum));
+        $buf = json_encode(array($data,$chksum));
         setcookie('ari_auth',$buf,time()+365*24*60*60,'/');
       }
 
```
