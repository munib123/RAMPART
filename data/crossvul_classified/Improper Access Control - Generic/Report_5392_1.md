# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 260-300 of the vulnerable file.

function renderAction(array $parms=array()) {
    global $user, $db;

    //Get some info about the controller
//    $baseControllerName = expModules::getControllerName($parms['controller']);
    $fullControllerName = expModules::getControllerClassName($parms['controller']);
    if (expModules::controllerExists($fullControllerName)) {
        $controllerClass = new ReflectionClass($fullControllerName);
    } else {
        return sprintf(gt('The module "%s" was not found in the system'), $parms['controller']);
    }

    if (isset($parms['view'])) $parms['view'] = urldecode($parms['view']);
    // Figure out the action to use...if the specified action doesn't exist then we look for the showall action.
    if ($controllerClass->hasMethod($parms['action'])) {
        $action = $parms['action'];
        /* TODO:  Not sure if we need to check for private methods to be here. FJD
		$meth = $controllerClass->getMethod($action);
        if ($meth->isPrivate()) expQueue::flashAndFlow('error', gt('The requested action could not be performed: Action not found'));*/
    } elseif ($controllerClass->hasMethod('showall')) {
        $parms['action'] = 'showall';
        $action = 'showall';
    } else {
        expQueue::flashAndFlow('error', gt('The requested action could not be performed: Action not found'));
    }

    // initialize the controller.
    $src = isset($parms['src']) ? $parms['src'] : null;
    $controller = new $fullControllerName($src, $parms);

    //Set up the correct template to use for this action
    global $template;
    $view = !empty($parms['view']) ? $parms['view'] : $action;
    $template = expTemplate::get_template_for_action($controller, $view, $controller->loc);

    //setup default model(s) for this controller's actions to use
    foreach ($controller->getModels() as $model) {
        $controller->$model = new $model(null,false,false);   //added null,false,false to reduce unnecessary queries. FJD
        // flag for needing approval check
        if ($controller->$model->supports_revisions && ENABLE_WORKFLOW) {
            $uilevel = 99;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -277,6 +277,7 @@
 		$meth = $controllerClass->getMethod($action);
         if ($meth->isPrivate()) expQueue::flashAndFlow('error', gt('The requested action could not be performed: Action not found'));*/
     } elseif ($controllerClass->hasMethod('showall')) {
+        //note every invalid command gets converted to 'showall'
         $parms['action'] = 'showall';
         $action = 'showall';
     } else {
@@ -402,39 +403,43 @@
         }
     }
 
+    // deal with lower case only to prevent hacking reflection function names
+    $lc_perms = array_change_key_case($perms);
+    $lc_perm_action = strtolower($perm_action);
+    $lc_common_action = strtolower($common_action);
     //FIXME? if the assoc $perm doesn't exist, the 'action' will ALWAYS be allowed, e.g., default is to allow action
-    if (array_key_exists($perm_action, $perms)) {
+    if (array_key_exists($lc_perm_action, $lc_perms)) {
         if (!expPermissions::check($perm_action, $controller->loc)) {
             if (expTheme::inAction()) {
-                flash('error', gt("You don't have permission to")." ".$perms[$perm_action]);
+                flash('error', gt("You don't have permission to")." ".$lc_perms[$lc_perm_action]);
                 notfoundController::handle_not_authorized();
                 expHistory::returnTo('viewable');
             } else {
                 return false;
             }
         }
-    } elseif (array_key_exists($common_action, $perms)) {
+    } elseif (array_key_exists($lc_common_action, $lc_perms)) {
         if (!expPermissions::check($common_action, $controller->loc)) {
             if (expTheme::inAction()) {
-                flash('error', gt("You don't have permission to")." ".$perms[$common_action]);
+                flash('error', gt("You don't have permission to")." ".$lc_perms[$lc_common_action]);
                 notfoundController::handle_not_authorized();
                 expHistory::returnTo('viewable');
             } else {
                 return false;
             }
         }
-    } elseif (array_key_exists($perm_action, $controller->requires_login)) {
+    } elseif (array_key_exists($lc_perm_action, $controller->requires_login)) {
         // check if the action requires the user to at least be logged in
         if (!$user->isLoggedIn()) {
-            $msg = empty($controller->requires_login[$perm_action]) ? gt("You must be logged in to perform this action") : gt($controller->requires_login[$perm_action]);
+            $msg = empty($controller->requires_login[$lc_perm_action]) ? gt("You must be logged in to perform this action") : gt($controller->requires_login[$lc_perm_action]);
             flash('error', $msg);
             notfoundController::handle_not_authorized();
             expHistory::redirecto_login();
         }
-    } elseif (array_key_exists($common_action, $controller->requires_login)) {
-        // check if the action requires the user to at least be logged in
+    } elseif (array_key_exists($lc_common_action, $controller->requires_login)) {
+        // check if the common action requires the user to at least be logged in
         if (!$user->isLoggedIn()) {
-            $msg = empty($controller->requires_login[$common_action]) ? gt("You must be logged in to perform this action") : gt($controller->requires_login[$common_action]);
+            $msg = empty($controller->requires_login[$lc_common_action]) ? gt("You must be logged in to perform this action") : gt($controller->requires_login[$lc_common_action]);
             flash('error', $msg);
             notfoundController::handle_not_authorized();
             expHistory::redirecto_login();
```
