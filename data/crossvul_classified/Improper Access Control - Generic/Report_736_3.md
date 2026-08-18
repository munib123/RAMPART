# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 736_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `736_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 23-63 of the vulnerable file.


    /* Static get */
    function staticGet($k,$v=NULL) { return DB_DataObject::staticGet('db_Users',$k,$v); }

    /* the code above is auto generated do not remove the tag below */
    ###END_AUTOCODE

    const SUPERADMIN = 0;
    const SITEADMIN  = 1;
    const USER       = 2;

    static $status_names = array(
        self::SUPERADMIN => 'superuser',
        self::SITEADMIN  => 'siteadmin',
        self::USER       => 'user'
    );

    /** Verify user credentials and register user in session if successful.
      * Requires fields 'backend_login', 'username' and 'password' to be set in $_REQUEST
      *   backend_login: must be set or this method won't try to authenticate
      *  @return user instance if login is successful, -1 if login failed, false if no login credentials were found.
      */
    static function authenticate() {
        if (isset($_REQUEST['backend_login'])) {
            $user = DB_DataObject::factory('users');
            $user->active = true;
            $user->name = $_REQUEST['username'];
            $user->find(true);

            // Don't look whether that user exists, so we give less timing information
            // Instead, rely only on having a matching password
            $proffered_password = $_REQUEST['password'];
            if (in_array(
                $user->password,
                self::password_hashes($proffered_password, $user->password_salt)
            )) {
                // Regenerate the session ID, unless it's an IE we're talking to which would use the old session ID to load the frame contents
                // Remove this guard once we no longer use frames
                if(!preg_match('/(?i)msie /', $_SERVER['HTTP_USER_AGENT'])) {
                    session_regenerate_id();
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,14 +40,21 @@
     /** Verify user credentials and register user in session if successful.
       * Requires fields 'backend_login', 'username' and 'password' to be set in $_REQUEST
       *   backend_login: must be set or this method won't try to authenticate
+      *  @param $allpass optional parameter to skip password check
       *  @return user instance if login is successful, -1 if login failed, false if no login credentials were found.
       */
-    static function authenticate() {
+    static function authenticate($allpass=false) {
         if (isset($_REQUEST['backend_login'])) {
             $user = DB_DataObject::factory('users');
             $user->active = true;
             $user->name = $_REQUEST['username'];
-            $user->find(true);
+            $found = $user->find(true);
+
+            if ($found && $allpass) {
+                Log::debug("Logging in user '$user->name' without checking password");
+                $user->login();
+                return true;
+            }
 
             // Don't look whether that user exists, so we give less timing information
             // Instead, rely only on having a matching password
```
