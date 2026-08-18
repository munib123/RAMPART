# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5403_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5403_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

 * @package Subsystems
 * @subpackage Subsystems
 */

class expRouter {

    private $maps = array();
    public  $url_parts = '';
    public  $current_url = '';
    /**
     * Type of url
     * either 'base' (default page), 'page', 'action', or 'malformed'
     * @var string
     */
    public  $url_type = '';
    /**
     * Style of url
     * either 'sef' or 'query'
     * @var string
     */
    public  $url_style = '';
    public  $params = array();
    public  $sefPath = null;

    function __construct() {
        self::getRouterMaps();
    }

    /**
     * remove trailing slash
     *
     * @param $fulllink
     *
     * @return string
     */
    public static function cleanLink($fulllink)
    {
        if(substr($fulllink, -1) == '/') $fulllink = substr($fulllink, 0, -1);
        return $fulllink;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,9 +38,9 @@
      * either 'sef' or 'query'
      * @var string
      */
-    public  $url_style = '';
+    private $url_style = '';
     public  $params = array();
-    public  $sefPath = null;
+    private $sefPath = null;
 
     function __construct() {
         self::getRouterMaps();
@@ -189,7 +189,11 @@
     public function routeRequest() {
         global $user;
 
-        // strip out possible xss exploits via url
+        // start splitting the URL into it's different parts
+        $this->splitURL();
+        // edebug($this,1);
+
+        // strip out possible xss exploits via old school url
         foreach ($_GET as $key=>$var) {
             if (is_string($var) && strpos($var,'">')) {
                 unset(
@@ -198,34 +202,36 @@
                 );
             }
         }
+        //fixme only old school url and forms have these variables here
         // conventional method to ensure the 'id' is only an id
         if (isset($_REQUEST['id'])) {
+            $_REQUEST['id'] = intval($_REQUEST['id']);
             if (isset($_GET['id']))
-                $_GET['id'] = intval($_GET['id']);
+                $_GET['id'] = $_REQUEST['id'];
             if (isset($_POST['id']))
-                $_POST['id'] = intval($_POST['id']);
-
-            $_REQUEST['id'] = intval($_REQUEST['id']);
+                $_POST['id'] = $_REQUEST['id'];
         }
         // do the same for the other id's
         foreach ($_REQUEST as $key=>$var) {
             if (is_string($var) && strlen($key) >= 3 && strrpos($key,'_id',-3) !== false) {
+                $_REQUEST[$key] = intval($_REQUEST[$key]);
                 if (isset($_GET[$key]))
-                    $_GET[$key] = intval($_GET[$key]);
+                    $_GET[$key] = $_REQUEST[$key];
                 if (isset($_POST[$key]))
-                    $_POST[$key] = intval($_POST[$key]);
-
-                $_REQUEST[$key] = intval($_REQUEST[$key]);
+                    $_POST[$key] = $_REQUEST[$key];
+            }
+            if ($key == 'src') {
+                $_REQUEST[$key] = preg_replace("/[^A-Za-z0-9@-]/", '', $_REQUEST[$key]);
+                if (isset($_GET[$key]))
+                    $_GET[$key] = $_REQUEST[$key];
+                if (isset($_POST[$key]))
+                    $_POST[$key] = $_REQUEST[$key];
             }
         }
         if (empty($user->id) || (!empty($user->id) && !$user->isAdmin())) {  //FIXME why would $user be empty here unless $db is down?
 //            $_REQUEST['route_sanitized'] = true;//FIXME debug test
             expString::sanitize($_REQUEST);  // strip other exploits like sql injections
         }
-
-        // start splitting the URL into it's different parts
-        $this->splitURL();
-        // edebug($this,1);
 
         if ($this->url_style == 'sef') {
             if ($this->url_type == 'page' || $this->url_type == 'base') {
@@ -248,8 +254,7 @@
                     $module = !empty($_POST['controller']) ? expString::sanitize($_POST['controller']) : expString::sanitize($_POST['module']);
                     // Figure out if this is module or controller request - WE ONLY NEED THIS CODE UNTIL WE PULL OUT THE OLD MODULES
                     if (expModules::controllerExists($module)) {
-                        $_POST['controller'] = $module;
-                        $_REQUEST['controller'] = $module;
+                        $_POST['controller'] = $_REQUEST['controller'] = $module;
                     }
                 }
             }
@@ -305,6 +310,9 @@
         $db->insertObject($trackingObject,'tracking_rawdata');
     }
 
+    /**
+     * Assign url_type & url_style
+     */
     public function splitURL() {
         global $db;
 
@@ -317,19 +325,23 @@
 
             // remove empty first and last url_parts if they exist
             //if (empty($this->url_parts[count($this->url_parts)-1])) array_pop($this->url_parts);
-            if ($this->url_parts[count($this->url_parts)-1] == '') array_pop($this->url_parts);
-            if (empty($this->url_parts[0])) array_shift($this->url_parts);
+            if ($this->url_parts[count($this->url_parts)-1] == '')
+                array_pop($this->url_parts);
+            if (empty($this->url_parts[0]))
+                array_shift($this->url_parts);
+            else
+                $this->url_parts[0] = expString::escape($this->url_parts[0]);
 
             if (count($this->url_parts) < 1 || (empty($this->url_parts[0]) && count($this->url_parts) == 1) ) {
                 $this->url_type = 'base';  // no params
-            } elseif (count($this->url_parts) == 1 || $db->selectObject('section', "sef_name='" . substr($this->sefPath,1) . "'") != null) {
+            } elseif (count($this->url_parts) == 1 || $db->selectObject('section', "sef_name='" . substr($this->sefPath, 1) . "'") != null) {
                 $this->url_type = 'page';  // single param is page name
             } elseif ($_SERVER['REQUEST_METHOD'] == 'POST') {
                 $this->url_type = 'post';  // params via form/post
             } else {
                 // take a peek and see if a page exists with the same name as the first value...if so we probably have a page with
                 // extra perms...like printerfriendly=1 or ajax_action=1;
-                if (($db->selectObject('section', "sef_name='" . $this->url_parts[0] . "'") != null) && (in_array(array('printerfriendly','exportaspdf','ajax_action'), $this->url_parts))) {
+                if (($db->selectObject('section', "sef_name='" . $this->url_parts[0]) . "'" != null) && (in_array(array('printerfriendly','exportaspdf','ajax_action'), $this->url_parts))) {
                     $this->url_type = 'page';
                 } else {
                     $this->url_type = 'action';
@@ -337,7 +349,7 @@
             }
             $this->params = $this->convertPartsToParams();
         } elseif ($_SERVER['REQUEST_METHOD'] == 'POST') {
-            $this->url_style = 'sef';
+            $this->url_style = 'sef';  // even if it's old school, they all come in the same
             $this->url_type = 'post';
             $this->params = $this->convertPartsToParams();
         } elseif (isset($_SERVER['REQUEST_URI'])) {
@@ -350,6 +362,7 @@
                 $sefPath = explode('%22%3E',$_SERVER['REQUEST_URI']);  // remove any attempts to close the command
                 $_SERVER['REQUEST_URI'] = $sefPath[0];
                 $this->url_style = 'query';
+                //note 'query' doesn't need $params
             }
         } else {
             $this->url_type = 'base';
@@ -362,6 +375,11 @@
         define('EXPORT_AS_PDF_LANDSCAPE', (isset($_REQUEST['landscapepdf']) || isset($this->params['landscapepdf'])) ? 1 : 0);
     }
 
+    /**
+     * Set up for page request, but check store category/product also
+     *
+     * @return bool
+     */
     public function routePageRequest() {
 //        global $db;
 
@@ -430,7 +448,7 @@
                     return $this->routeActionRequest();
                 }
 //fixme we may want to log missed pages (no existing store cat/product) requests and set up/use a redirect table (404)??
-//fixme and we may also want to log any redirects taken??
+//fixme and we may also want to log any redirects taken from that table??
                 return false;
             }
             #########################################################
@@ -493,7 +511,8 @@
                     }
                 }
 
-                $this->params = $this->convertPartsToParams();
+                $this->params = $this->convertPartsToParams(); // update params to new re-mapped url_parts
+                //fixme do we need to re-sanitize them???
                 return true;
             }
         }
@@ -501,6 +520,11 @@
         return false;
     }
 
+    /**
+     * Check and set up for an action request
+     *
+     * @return bool
+     */
     public function routeActionRequest() {
... (diff truncated)
```
