# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4482_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4482_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php
/**
 * This file is part of the Cockpit project.
 *
 * (c) Artur Heinze - 🅰🅶🅴🅽🆃🅴🅹🅾, http://agentejo.com
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cockpit\Controller;

class Auth extends \LimeExtra\Controller {


    public function check() {

        if ($data = $this->param('auth')) {

            if (isset($data['user']) && $this->app->helper('utils')->isEmail($data['user'])) {
                $data['email'] = $data['user'];
                $data['user']  = '';
            }

            if (!$this->app->helper('csfr')->isValid('login', $this->param('csfr'), true)) {
                $this->app->trigger('cockpit.authentication.failed', [$data, 'Csfr validation failed']);
                return ['success' => false, 'error' => 'Csfr validation failed'];
            }

            $user = $this->module('cockpit')->authenticate($data);

            if ($user && !$this->module('cockpit')->hasaccess('cockpit', 'backend', @$user['group'])) {
                $user = null;
            }

            if ($user) {
                $this->app->trigger('cockpit.authentication.success', [&$user]);
                $this->module('cockpit')->setUser($user);
            } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,10 @@
     public function check() {
 
         if ($data = $this->param('auth')) {
+
+            if (!\is_string($data['user']) || !\is_string($data['password'])) {
+                return ['success' => false, 'error' => 'Pre-condition failed'];
+            }
 
             if (isset($data['user']) && $this->app->helper('utils')->isEmail($data['user'])) {
                 $data['email'] = $data['user'];
@@ -128,13 +132,21 @@
 
         if ($token = $this->param('token')) {
 
+            if (!\is_string($token)) {
+                return false;
+            }
+
             $user = $this->app->storage->findOne('cockpit/accounts', ['_reset_token' => $token]);
 
             if (!$user) {
                 return false;
             }
 
-            $user['md5email'] = md5($user['email']);
+            $user = [
+                'md5email' => md5($user['email']),
+                'user' => $user['name'],
+                'name' => $user['user'],
+            ];
 
             return $this->render('cockpit:views/layouts/newpassword.php', compact('user', 'token'));
         }
@@ -146,6 +158,10 @@
     public function resetpassword() {
 
         if ($token = $this->param('token')) {
+
+            if (!\is_string($token)) {
+                return false;
+            }
 
             $user = $this->app->storage->findOne('cockpit/accounts', ['_reset_token' => $token]);
             $password = trim($this->param('password'));
```
