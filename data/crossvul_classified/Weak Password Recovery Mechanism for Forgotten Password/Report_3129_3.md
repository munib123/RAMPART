# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 3129_3
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3129_3`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.


class ResetPasswordController
{

    public function indexAction()
    {
        if (App::user()->isAuthenticated()) {
            return App::redirect();
        }

        return [
            '$view' => [
                'title' => __('Reset'),
                'name' => 'system/user/reset-request.php',
            ],
            'error' => ''
        ];
    }

    /**
     * @Request({"email": "string"})
     */
    public function requestAction($email)
    {
        try {

            if (App::user()->isAuthenticated()) {
                return App::redirect();
            }

            if (!App::csrf()->validate()) {
                throw new Exception(__('Invalid token. Please try again.'));
            }

            if (empty($email)) {
                throw new Exception(__('Enter a valid email address.'));
            }

            if (!$user = User::findByEmail($email)) {
                throw new Exception(__('Unknown email address.'));
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     }
 
     /**
-     * @Request({"email": "string"})
+     * @Request({"email"})
      */
     public function requestAction($email)
     {
@@ -51,9 +51,8 @@
                 throw new Exception(__('Your account has not been activated or is blocked.'));
             }
 
-            $user->activation = App::get('auth.random')->generateString(32);
-
-            $url = App::url('@user/resetpassword/confirm', ['user' => $user->username, 'key' => $user->activation], 0);
+            $key = App::get('auth.random')->generateString(32);
+            $url = App::url('@user/resetpassword/confirm', compact('key'), 0);
 
             try {
 
@@ -67,6 +66,7 @@
                 throw new Exception(__('Unable to send confirmation link.'));
             }
 
+            $user->activation = $key;
             $user->save();
 
             App::message()->success(__('Check your email for the confirmation link.'));
@@ -85,15 +85,26 @@
     }
 
     /**
-     * @Request({"user", "key"})
+     * @Request({"key", "password"})
      */
-    public function confirmAction($username = "", $activation = "")
+    public function confirmAction($activation = '', $password = '')
     {
-        if (empty($username) || empty($activation) || !$user = User::where(compact('username', 'activation'))->first()) {
+        if ($activation and $user = User::where(compact('activation'))->first()) {
+
+            App::session()->set('activation', [
+                'key' => $activation,
+                'user' => $user->id,
+            ]);
+
+            $user->activation = null;
+            $user->save();
+        }
+
+        if (!$data = App::session()->get('activation') or $data['key'] != $activation) {
             App::abort(400, __('Invalid key.'));
         }
 
-        if ($user->isBlocked()) {
+        if (!$user = User::find($data['user']) or $user->isBlocked()) {
             App::abort(400, __('Your account has not been activated or is blocked.'));
         }
 
@@ -105,8 +116,6 @@
                     throw new Exception(__('Invalid token. Please try again.'));
                 }
 
-                $password = App::request()->request->get('password');
-
                 if (empty($password)) {
                     throw new Exception(__('Enter password.'));
                 }
@@ -115,10 +124,11 @@
                     throw new Exception(__('Invalid password.'));
                 }
 
+                $user->activation = null;
                 $user->password = App::get('auth.password')->hash($password);
-                $user->activation = null;
                 $user->save();
 
+                App::session()->remove('activation');
                 App::message()->success(__('Your password has been reset.'));
 
                 return App::redirect('@user/login');
@@ -133,7 +143,6 @@
                 'title' => __('Reset Confirm'),
                 'name' => 'system/user/reset-confirm.php'
             ],
-            'username' => $username,
             'activation' => $activation,
             'error' => isset($error) ? $error : ''
         ];
```
