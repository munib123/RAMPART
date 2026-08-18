# CrossVul Fix Pair: Use of Insufficiently Random Values in php
**Pair ID:** 1954_2
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1954_2`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

      if (ttValidEmail($cl_login)) {
        $login = ttUserHelper::getUserByEmail($cl_login);
        if ($login)
          $cl_login = $login;
        else
          $err->add($i18n->get('error.no_login'));
      } else
        $err->add($i18n->get('error.no_login'));
    }
  }

  if ($err->no()) {
    $user = new ttUser($cl_login); // Note: reusing $user from initialize.php here.

    // Protection against flooding user mailbox with too many password reset emails.
    if (ttUserHelper::recentRefExists($user->id)) $err->add($i18n->get('error.access_denied'));
  }

  if ($err->no()) {
    // Prepare and save a temporary reference for user.
    $temp_ref = md5(uniqid());
    ttUserHelper::saveTmpRef($temp_ref, $user->id);

    $user_i18n = null;
    if ($user->lang != $i18n->lang) {
      $user_i18n = new I18n();
      $user_i18n->load($user->lang);
    } else
      $user_i18n = &$i18n;

    // Where do we email to?
    $receiver = null;
    if ($user->email)
      $receiver = $user->email;
    else {
      if (ttValidEmail($cl_login))
        $receiver = $cl_login;
      else
        $err->add($i18n->get('error.no_email'));
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,10 @@
 
   if ($err->no()) {
     // Prepare and save a temporary reference for user.
-    $temp_ref = md5(uniqid());
+    $cryptographically_strong = true;
+    $random_bytes = openssl_random_pseudo_bytes(16, $cryptographically_strong);
+    if ($random_bytes === false) die ("openssl_random_pseudo_bytes function call failed...");
+    $temp_ref = bin2hex($random_bytes);
     ttUserHelper::saveTmpRef($temp_ref, $user->id);
 
     $user_i18n = null;
```
