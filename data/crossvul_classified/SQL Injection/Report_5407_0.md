# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5407_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5407_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

# GPL: http://www.gnu.org/licenses/gpl.txt
#
##################################################

/**
 * @subpackage Controllers
 * @package Modules
 */

class notfoundController extends expController {
    protected $add_permissions = array(
        'showall'=>'Showall',
        'show'=>'Show'
    );

    static function displayname() { return gt("Page Not Found"); }
    static function description() { return gt("This controller handles routing to the appropriate place when pages are not found."); }
    static function hasSources() { return false; }
    static function hasViews() { return false; }
    static function hasContent() { return false; }
    
    public function handle() {
        global $router;

        $args = array_merge(array('controller'=>'notfound', 'action'=>'page_not_found'), $router->url_parts);   
        header("Refresh: 0; url=".$router->makeLink($args), false, 404);
    }
    
    public function page_not_found() {
        global $router;

        header(':', true, 404);
        $params = $router->params;
        unset(
            $params['controller'],
            $params['action']
        );
        $terms = empty($params[0]) ? '' : $params[0];
        if (empty($terms) && !empty($params['title'])) $terms = $params['title'];
        expCSS::pushToHead(array(
//	        "unique"=>"search-results",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,14 +32,14 @@
     static function hasSources() { return false; }
     static function hasViews() { return false; }
     static function hasContent() { return false; }
-    
+
     public function handle() {
         global $router;
 
-        $args = array_merge(array('controller'=>'notfound', 'action'=>'page_not_found'), $router->url_parts);   
+        $args = array_merge(array('controller'=>'notfound', 'action'=>'page_not_found'), $router->url_parts);
         header("Refresh: 0; url=".$router->makeLink($args), false, 404);
     }
-    
+
     public function page_not_found() {
         global $router;
 
@@ -60,7 +60,7 @@
         if (get_magic_quotes_gpc()) {
             $terms = stripslashes($terms);
         }
-        $terms = htmlspecialchars($terms);
+        $terms = expString::escape(htmlspecialchars($terms));
 
         // check for server requested error documents here instead of treating them as a search request
         if ($terms == SITE_404_FILE) {
```
