# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5278_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5278_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 745-785 of the vulnerable file.

    public static function runAction()
    {
        global $user;

        if (self::inAction()) {
            if (!AUTHORIZED_SECTION && !expJavascript::inAjaxAction())
                notfoundController::handle_not_authorized();
//			if (expSession::is_set("themeopt_override")) {
//				$config = expSession::get("themeopt_override");
//				echo "<a href='".$config['mainpage']."'>".$config['backlinktext']."</a><br /><br />";
//			}

            //FIXME clean our passed parameters
//            foreach ($_REQUEST as $key=>$param) {  //FIXME need array sanitizer
//                $_REQUEST[$key] = expString::sanitize($param);
//            }
//            if (empty($_REQUEST['route_sanitized'])) {
            if (!$user->isAdmin())
                expString::sanitize($_REQUEST);
//            } elseif (empty($_REQUEST['array_sanitized'])) {
                $tmp =1;  //FIXME we've already sanitized at this point
//            } else {
//                $tmp =1;  //FIXME we've already sanitized at this point
//            }

            //FIXME: module/controller glue code..remove ASAP
            $module = empty($_REQUEST['controller']) ? $_REQUEST['module'] : $_REQUEST['controller'];
//			$isController = expModules::controllerExists($module);

//			if ($isController && !isset($_REQUEST['_common'])) {
            if (expModules::controllerExists($module)) {
                // this is being set just in case the url said module=modname instead of controller=modname
                // with SEF URls turned on its not really an issue, but with them off some of the links
                // aren't being made correctly...depending on how the {link} plugin was used in the view.
                $_REQUEST['controller'] = $module;

//                if (!isset($_REQUEST['action'])) $_REQUEST['action'] = 'showall';
//                if (isset($_REQUEST['view']) && $_REQUEST['view'] != $_REQUEST['action']) {
//                    $test = explode('_',$_REQUEST['view']);
//                    if ($test[0] != $_REQUEST['action']) {
//                        $_REQUEST['view'] = $_REQUEST['action'].'_'.$_REQUEST['view'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -762,7 +762,7 @@
             if (!$user->isAdmin())
                 expString::sanitize($_REQUEST);
 //            } elseif (empty($_REQUEST['array_sanitized'])) {
-                $tmp =1;  //FIXME we've already sanitized at this point
+//                $tmp =1;  //FIXME we've already sanitized at this point
 //            } else {
 //                $tmp =1;  //FIXME we've already sanitized at this point
 //            }
@@ -843,7 +843,8 @@
 ////                $_GET[$key] = $value;
 //                $_GET[$key] = expString::sanitize($value);
 //            }
-            if (!$user->isAdmin()) expString::sanitize($_GET);
+            if (!$user->isAdmin())
+                expString::sanitize($_GET);
         }
         //if (isset($['_common'])) $actfile = "/common/actions/" . $_REQUEST['action'] . ".php";
 
```
