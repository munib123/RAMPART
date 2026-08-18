# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5327_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5327_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 268-309 of the vulnerable file.

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
            if (expSession::exists("uilevel")) $uilevel = expSession::get("uilevel");
            if (!expPermissions::check('approve', $controller->loc)) {
                $controller->$model->needs_approval = true;
            } elseif (isset($uilevel) && $uilevel == UILEVEL_PREVIEW) {
                $controller->$model->needs_approval = true;
            }
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -285,13 +285,13 @@
 
     // initialize the controller.
     $src = isset($parms['src']) ? $parms['src'] : null;
-    $controller = new $fullControllerName($src, $parms);    
-    
+    $controller = new $fullControllerName($src, $parms);
+
     //Set up the correct template to use for this action
     global $template;
     $view = !empty($parms['view']) ? $parms['view'] : $action;
     $template = expTemplate::get_template_for_action($controller, $view, $controller->loc);
-    
+
     //setup default model(s) for this controller's actions to use
     foreach ($controller->getModels() as $model) {
         $controller->$model = new $model(null,false,false);   //added null,false,false to reduce unnecessary queries. FJD
@@ -324,28 +324,30 @@
     }
 
     // check the perms for this action
-    $perms = $controller->permissions();
-    
+    $perms = $controller->permissions_all();
+
+    $common_action = null;
+    // action convention for controllers that manage more than one model (datatype).
+    // if you preface the name action name with a common crud action name we can check perms on
+    // it with the developer needing to specify any...better safe than sorry.
+    // i.e if the action is edit_mymodel it will be checked against the edit permission
+    if (stristr($parms['action'], '_'))
+        $parts = explode("_", $parms['action']);
+    else
+        $parts = preg_split('/(?=[A-Z])/', $parms['action']);  // account for actions with camelCase action/perm such as editItem
+    $common_action = isset($parts[0]) ? $parts[0] : null;
     // we have to treat the update permission a little different..it's tied to the create/edit
     // permissions.  Really the only way this will fail will be if someone bypasses the perm check
     // on the edit form somehow..like a hacker trying to bypass the form and just submit straight to
     // the action. To safeguard, we'll catch if the action is update and change it either to create or
     // edit depending on whether an id param is passed to. that should be sufficient.
-    $common_action = null;
-    //FIXME do we also need to account for actions with camelcase action/perm such as editItem ???
-    if ($parms['action'] == 'update') {
+    if ($parms['action'] == 'update' || $common_action == 'update') {
         $perm_action = (!isset($parms['id']) || $parms['id'] == 0) ? 'create' : 'edit';
-    } elseif ($parms['action'] == 'edit' && (!isset($parms['id']) || $parms['id'] == 0)) {
+    } elseif (($parms['action'] == 'edit' || $common_action == 'edit') && (!isset($parms['id']) || $parms['id'] == 0)) {
         $perm_action = 'create';
     } elseif ($parms['action'] == 'saveconfig') {
         $perm_action = 'configure';
     } else {
-        // action convention for controllers that manage more than one model (datatype). 
-        // if you preface the name action name with a common crud action name we can check perms on 
-        // it with the developer needing to specify any...better safe than sorry.
-        // i.e if the action is edit_mymodel it will be checked against the edit permission
-        if (stristr($parms['action'], '_')) $parts = explode("_", $parms['action']);
-        $common_action = isset($parts[0]) ? $parts[0] : null;
         $perm_action = $parms['action'];
     }
 
@@ -424,7 +426,7 @@
     } elseif (array_key_exists($perm_action, $controller->requires_login)) {
         // check if the action requires the user to at least be logged in
         if (!$user->isLoggedIn()) {
-            $msg = empty($controller->requires_login[$perm_action]) ? gt("You must be logged in to perform this action") : $controller->requires_login[$perm_action];
+            $msg = empty($controller->requires_login[$perm_action]) ? gt("You must be logged in to perform this action") : gt($controller->requires_login[$perm_action]);
             flash('error', $msg);
             notfoundController::handle_not_authorized();
             expHistory::redirecto_login();
@@ -432,16 +434,16 @@
     } elseif (array_key_exists($common_action, $controller->requires_login)) {
         // check if the action requires the user to at least be logged in
         if (!$user->isLoggedIn()) {
-            $msg = empty($controller->requires_login[$common_action]) ? gt("You must be logged in to perform this action") : $controller->requires_login[$common_action];
+            $msg = empty($controller->requires_login[$common_action]) ? gt("You must be logged in to perform this action") : gt($controller->requires_login[$common_action]);
             flash('error', $msg);
             notfoundController::handle_not_authorized();
             expHistory::redirecto_login();
         }
-    } 
-    
+    }
+
     // register this controllers permissions to the view for in view perm checks
     $template->register_permissions(array_keys($perms), $controller->loc);
-    
+
     // globalizing $user inside all templates
     $template->assign('user', $user);
 
@@ -486,7 +488,7 @@
     $link = (!is_array($params)) ? $params : $router->makeLink($params, false, $secure);
     header("Location: " . $link);
     exit();
-}   
+}
 
 function flash($name, $msg) {
     expQueue::flash($name, $msg);
@@ -514,7 +516,7 @@
  */
 function assign_to_template(array $vars=array()) {
     global $template;
-    
+
     if (empty($template) || count($vars) == 0) return false;
     foreach ($vars as $key=>$val) {
         $template->assign($key, $val);
@@ -540,7 +542,7 @@
     $controller = new stdClass();
     $controller->baseclassname = empty($controllername) ? 'common' : $controllername;
     $controller->loc = $loc;
-    
+
     $themepath = BASE . 'themes/' . DISPLAY_THEME . '/modules/common/views/' . $controllername . '/' . $view . '.tpl';
     $basenewuipath = BASE . 'framework/modules/common/views/' . $controllername . '/' . $view . '.newui.tpl';
     $basepath = BASE . 'framework/modules/common/views/' . $controllername . '/' . $view . '.tpl';
@@ -581,19 +583,19 @@
     return expTemplate::get_config_templates($controller, $loc);
 
 //    global $db;
-    
+
     // set paths we will search in for the view
     $commonpaths = array(
         BASE.'framework/modules/common/views/configure',
         BASE.'themes/'.DISPLAY_THEME.'/modules/common/views/configure',
     );
-    
+
     $modpaths = array(
         $controller->viewpath.'/configure',
 	    BASE.'themes/'.DISPLAY_THEME.'/modules/'.$controller->relative_viewpath.'/configure'
     );
-    
-    // get the common configuration files    
+
+    // get the common configuration files
     $common_views = expTemplate::find_config_views($commonpaths, $controller->remove_configs);
     foreach ($common_views as $key=>$value) {
         $common_views[$key]['name'] = gt($value['name']);
@@ -608,7 +610,7 @@
         $module_views[$key]['name'] = gt($value['name']);
     }
 
-    // look for a config form for this module's current view    
+    // look for a config form for this module's current view
 //    $controller->loc->mod = expModules::getControllerClassName($controller->loc->mod);
     //check to see if hcview was passed along, indicating a hard-coded module
 //    if (!empty($controller->params['hcview'])) {
@@ -625,7 +627,7 @@
 //            $module_views[$viewname]['file'] =$path.'/'.$viewconfig;
 //        }
 //    }
-    
+
     // sort the views highest to lowest by filename
     // we are reverse sorting now so our array merge
     // will overwrite property..we will run array_reverse
@@ -671,7 +673,7 @@
             }
         }
     }
-    
+
     return $views;
 }
 
@@ -759,12 +761,12 @@
 //    $controller = new $controllerName();
     $controller = expModules::getController($ctl);
 
-    // set path information 
+    // set path information
     $paths = array(
         $controller->viewpath,
         BASE.'themes/'.DISPLAY_THEME.'/modules/'.$controller->relative_viewpath,
     );
-    
+
     $views = array();
     foreach ($paths as $path) {
... (diff truncated)
```
