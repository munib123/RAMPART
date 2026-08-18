# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5372_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5372_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 192-232 of the vulnerable file.

        // strip out possible xss exploits via url
        foreach ($_GET as $key=>$var) {
            if (is_string($var) && strpos($var,'">')) {
                unset(
                    $_GET[$key],
                    $_REQUEST[$key]
                );
            }
        }
        // conventional method to ensure the 'id' is only an id
        if (isset($_REQUEST['id'])) {
            if (isset($_GET['id']))
                $_GET['id'] = intval($_GET['id']);
            if (isset($_POST['id']))
                $_POST['id'] = intval($_POST['id']);

            $_REQUEST['id'] = intval($_REQUEST['id']);
        }
        // do the same for the other id's
        foreach ($_REQUEST as $key=>$var) {
            if (is_string($var) && strrpos($key,'_id',-3) !== false) {
                if (isset($_GET[$key]))
                    $_GET[$key] = intval($_GET[$key]);
                if (isset($_POST[$key]))
                    $_POST[$key] = intval($_POST[$key]);

                $_REQUEST[$key] = intval($_REQUEST[$key]);
            }
        }
        if (empty($user->id) || (!empty($user->id) && !$user->isAdmin())) {  //FIXME why would $user be empty here unless $db is down?
//            $_REQUEST['route_sanitized'] = true;//FIXME debug test
            expString::sanitize($_REQUEST);  // strip other exploits like sql injections
        }

        // start splitting the URL into it's different parts
        $this->splitURL();
        // edebug($this,1);

        if ($this->url_style == 'sef') {
            if ($this->url_type == 'page' || $this->url_type == 'base') {
                $ret = $this->routePageRequest();               // if we hit this the formatting of the URL looks like the user is trying to go to a page.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,7 +209,7 @@
         }
         // do the same for the other id's
         foreach ($_REQUEST as $key=>$var) {
-            if (is_string($var) && strrpos($key,'_id',-3) !== false) {
+            if (is_string($var) && strlen($key) >= 3 && strrpos($key,'_id',-3) !== false) {
                 if (isset($_GET[$key]))
                     $_GET[$key] = intval($_GET[$key]);
                 if (isset($_POST[$key]))
```
