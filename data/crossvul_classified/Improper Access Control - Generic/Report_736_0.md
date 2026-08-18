# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 736_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `736_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php
/** Initialization operations for the backend
  * Ensures a logged-in user and initializes some globals.
  * @package Aquarius.backend
*/

Log::backtrace('backend');

/* Use sessions in backend */
    $aquarius->session_start();


/* Process logins & load logged in user */
    require_once "db/Users.php";
    $login_status = db_Users::authenticate();
                
    // Redirect to frontend if user wants to
    if ($login_status instanceof db_User && isset($_REQUEST['login_frontend'])) {
        header('Location:'.PROJECT_URL);
        exit;
    }

    $user = db_Users::authenticated();

    $request_params = array(
        'request' => clean_magic($_REQUEST),
        'server' => $_SERVER,
        'require_active' => false,
        'user' => $user
    );
    
    // Determine the preset language for working with content
    // Actions often override this and have their own lg specifiers
    $lg_detection = new Language_Detection;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,9 +11,10 @@
 
 
 /* Process logins & load logged in user */
+    $allpass = $aquarius->conf('admin/allpass');
     require_once "db/Users.php";
-    $login_status = db_Users::authenticate();
-                
+    $login_status = db_Users::authenticate($allpass);
+
     // Redirect to frontend if user wants to
     if ($login_status instanceof db_User && isset($_REQUEST['login_frontend'])) {
         header('Location:'.PROJECT_URL);
```
