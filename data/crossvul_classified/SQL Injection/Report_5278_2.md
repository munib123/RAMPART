# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5278_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5278_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 181-223 of the vulnerable file.

     * @return string
     */
    public function plainPath() {
        $params = $this->params;
        unset($params['src']);
        return $this->makeLink($params);
    }

    public function routeRequest() {
        global $user;

        // strip out possible xss exploits via url
        foreach ($_GET as $key=>$var) {
            if (is_string($var) && strpos($var,'">')) {
                unset(
                    $_GET[$key],
                    $_REQUEST[$key]
                );
            }
        }
        // conventional method to ensure the 'id' is an id
        if (isset($_GET['id'])) {
            $_GET['id'] = intval($_GET['id']);
            $_REQUEST['id'] = intval($_REQUEST['id']);
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
                if (!$ret) $this->url_type = 'malformed';
            } elseif ($this->url_type == 'action') {
                $this->isMappedURL();                       //check for a router map
                $ret = $this->routeActionRequest();         // we didn't have a map for this URL.  Try to route it with this function.

                // if this url wasn't a valid section, or action then kill it.  It might not actually be a "bad" url, 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,10 +198,25 @@
                 );
             }
         }
-        // conventional method to ensure the 'id' is an id
-        if (isset($_GET['id'])) {
-            $_GET['id'] = intval($_GET['id']);
+        // conventional method to ensure the 'id' is only an id
+        if (isset($_REQUEST['id'])) {
+            if (isset($_GET['id']))
+                $_GET['id'] = intval($_GET['id']);
+            if (isset($_POST['id']))
+                $_POST['id'] = intval($_POST['id']);
+
             $_REQUEST['id'] = intval($_REQUEST['id']);
+        }
+        // do the same for the other id's
+        foreach ($_REQUEST as $key=>$var) {
+            if (is_string($var) && strrpos($key,'_id',-3) !== false) {
+                if (isset($_GET[$key]))
+                    $_GET[$key] = intval($_GET[$key]);
+                if (isset($_POST[$key]))
+                    $_POST[$key] = intval($_POST[$key]);
+
+                $_REQUEST[$key] = intval($_REQUEST[$key]);
+            }
         }
         if (empty($user->id) || (!empty($user->id) && !$user->isAdmin())) {  //FIXME why would $user be empty here unless $db is down?
 //            $_REQUEST['route_sanitized'] = true;//FIXME debug test
@@ -307,14 +322,14 @@
             
             if (count($this->url_parts) < 1 || (empty($this->url_parts[0]) && count($this->url_parts) == 1) ) {
                 $this->url_type = 'base';  // no params
-            } elseif (count($this->url_parts) == 1 || $db->selectObject('section', "sef_name='" . substr($db->escapeString($this->sefPath),1) . "'") != null) {
+            } elseif (count($this->url_parts) == 1 || $db->selectObject('section', "sef_name='" . substr($this->sefPath,1) . "'") != null) {
                 $this->url_type = 'page';  // single param is page name
             } elseif ($_SERVER['REQUEST_METHOD'] == 'POST') {
                 $this->url_type = 'post';  // params via form/post
             } else {
                 // take a peek and see if a page exists with the same name as the first value...if so we probably have a page with
                 // extra perms...like printerfriendly=1 or ajax_action=1;
-                if (($db->selectObject('section', "sef_name='" . $db->escapeString($this->url_parts[0]) . "'") != null) && (in_array(array('printerfriendly','exportaspdf','ajax_action'), $this->url_parts))) {
+                if (($db->selectObject('section', "sef_name='" . $this->url_parts[0] . "'") != null) && (in_array(array('printerfriendly','exportaspdf','ajax_action'), $this->url_parts))) {
                     $this->url_type = 'page';
                 } else {
                     $this->url_type = 'action';
@@ -547,7 +562,7 @@
         } else {
             $url .= urldecode((empty($_SERVER['REQUEST_URI'])) ? $_ENV['REQUEST_URI'] : $_SERVER['REQUEST_URI']);
         }
-        return expString::sanitize($url);
+        return expString::escape(expString::sanitize($url));
     }
 
     public static function encode($url) {
@@ -760,7 +775,7 @@
         if (substr($this->sefPath,-1) == "/") $this->sefPath = substr($this->sefPath,0,-1);
         // sanitize it
         $sefPath = explode('">',$this->sefPath);  // remove any attempts to close the command
-        $this->sefPath = expString::sanitize($sefPath[0]);
+        $this->sefPath = expString::escape(expString::sanitize($sefPath[0]));
     }
 
     public function getSection() {
```
