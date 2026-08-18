# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4000_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4000_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 89-129 of the vulnerable file.

        if ($port && $port != 443) {
            $host .= ':' . $port;
        }

        header('Location: https://' . $host . $_SERVER['REQUEST_URI']);
        exit;
    }
}

// trigger startup plugin hook
$startup = $RCMAIL->plugins->exec_hook('startup', array('task' => $RCMAIL->task, 'action' => $RCMAIL->action));
$RCMAIL->set_task($startup['task']);
$RCMAIL->action = $startup['action'];

// try to log in
if ($RCMAIL->task == 'login' && $RCMAIL->action == 'login') {
    $request_valid = $_SESSION['temp'] && $RCMAIL->check_request();
    $pass_charset  = $RCMAIL->config->get('password_charset', 'UTF-8');

    // purge the session in case of new login when a session already exists
    $RCMAIL->kill_session();

    $auth = $RCMAIL->plugins->exec_hook('authenticate', array(
            'host'  => $RCMAIL->autoselect_host(),
            'user'  => trim(rcube_utils::get_input_value('_user', rcube_utils::INPUT_POST)),
            'pass'  => rcube_utils::get_input_value('_pass', rcube_utils::INPUT_POST, true, $pass_charset),
            'valid' => $request_valid,
            'cookiecheck' => true,
    ));

    // Login
    if ($auth['valid'] && !$auth['abort']
        && $RCMAIL->login($auth['user'], $auth['pass'], $auth['host'], $auth['cookiecheck'])
    ) {
        // create new session ID, don't destroy the current session
        // it was destroyed already by $RCMAIL->kill_session() above
        $RCMAIL->session->remove('temp');
        $RCMAIL->session->regenerate_id(false);

        // send auth cookie if necessary
        $RCMAIL->session->set_auth_cookie();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,7 +106,9 @@
     $pass_charset  = $RCMAIL->config->get('password_charset', 'UTF-8');
 
     // purge the session in case of new login when a session already exists
-    $RCMAIL->kill_session();
+    if ($request_valid) {
+        $RCMAIL->kill_session();
+    }
 
     $auth = $RCMAIL->plugins->exec_hook('authenticate', array(
             'host'  => $RCMAIL->autoselect_host(),
@@ -180,13 +182,15 @@
         $RCMAIL->plugins->exec_hook('login_failed', array(
             'code' => $error_code, 'host' => $auth['host'], 'user' => $auth['user']));
 
-        $RCMAIL->kill_session();
+        if (!isset($_SESSION['user_id'])) {
+            $RCMAIL->kill_session();
+        }
     }
 }
 
 // end session
 else if ($RCMAIL->task == 'logout' && isset($_SESSION['user_id'])) {
-    $RCMAIL->request_security_check($mode = rcube_utils::INPUT_GET);
+    $RCMAIL->request_security_check(rcube_utils::INPUT_GET | rcube_utils::INPUT_POST);
 
     $userdata = array(
         'user' => $_SESSION['username'],
```
