# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 385_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `385_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 629-669 of the vulnerable file.

                        'captcha_error' => true,
                        'form_data_required' => 'captcha',
                        'form_data_module' => 'captcha'
                    );


                }
            }
        }
        $override = $this->app->event_manager->trigger('before_user_register', $params);

        if (is_array($override)) {
            foreach ($override as $resp) {
                if (isset($resp['error']) or isset($resp['success'])) {
                    return $resp;
                }
            }
        }

        if (defined('MW_API_CALL')) {
            if (isset($params['is_admin']) and $this->is_admin() == false) {
                unset($params['is_admin']);
            }
            if (isset($params['is_verified']) and $this->is_admin() == false) {
                unset($params['is_verified']);
            }
        }

        if (!isset($params['password']) or (isset($params['password']) and ($params['password']) == '')) {
            return array('error' => 'Please set password!');
        }

        if (get_option('form_show_password_confirmation', 'users') == 'y') {
            if (!isset($params['password2']) or (isset($params['password2']) and ($params['password2'] != $params['password']))) {
                return array('error' => 'Two password entries do not match!');
            }
        }

        if (!isset($params['username']) and !isset($params['email'])) {
            return array('error' => 'Please set username or email!');
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -646,6 +646,7 @@
         }
 
         if (defined('MW_API_CALL')) {
+
             if (isset($params['is_admin']) and $this->is_admin() == false) {
                 unset($params['is_admin']);
             }
@@ -901,6 +902,21 @@
             }
         }
         if ($force == false) {
+
+            if (isset($params['id'])) {
+                $validate_token = mw()->user_manager->csrf_validate($params);
+
+                if ($validate_token == false) {
+
+                    return array(
+                        'error' => _e('Confirm edit of profile', true),
+                        'form_data_required' => 'token',
+                        'form_data_module' => 'users/profile/confirm_edit'
+                    );
+
+                }
+            }
+
             if (isset($params['id']) and $params['id'] != 0) {
                 $adm = $this->is_admin();
                 if ($adm == false) {
@@ -923,6 +939,9 @@
                             return array('error' => 'You must be logged save your settings');
                         }
                     } else {
+
+
+
                         if (!isset($params['id'])) {
                             $params['id'] = $this->id();
                         }
```
