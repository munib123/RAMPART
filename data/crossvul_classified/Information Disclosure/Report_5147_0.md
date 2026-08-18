# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5147_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5147_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Form validation for configuration editor
 *
 * @package PhpMyAdmin
 */
namespace PMA\libraries\config;

use PMA\libraries\DatabaseInterface;

/**
 * Validation class for various validation functions
 *
 * Validation function takes two argument: id for which it is called
 * and array of fields' values (usually values for entire formset, as defined
 * in forms.inc.php).
 * The function must always return an array with an error (or error array)
 * assigned to a form element (formset name or field path). Even if there are
 * no errors, key must be set with an empty value.
 *
 * Validation functions are assigned in $cfg_db['_validators'] (config.values.php).
 *
 * @package PhpMyAdmin
 */
class Validator
{
    /**
     * Returns validator list
     *
     * @param ConfigFile $cf Config file instance
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 namespace PMA\libraries\config;
 
 use PMA\libraries\DatabaseInterface;
+use PMA\libraries\Util;
 
 /**
  * Validation class for various validation functions
@@ -280,6 +281,11 @@
             'Servers/1/SignonURL' => ''
         );
         $error = false;
+        if (empty($values['Servers/1/auth_type'])) {
+            $values['Servers/1/auth_type'] = '';
+            $result['Servers/1/auth_type'] = __('Invalid authentication type!');
+            $error = true;
+        }
         if ($values['Servers/1/auth_type'] == 'config'
             && empty($values['Servers/1/user'])
         ) {
@@ -308,14 +314,14 @@
         }
 
         if (! $error && $values['Servers/1/auth_type'] == 'config') {
-            $password = $values['Servers/1/nopassword'] ? null
-                : $values['Servers/1/password'];
+            $password = !empty($values['Servers/1/nopassword']) && $values['Servers/1/nopassword'] ? null
+                : (empty($values['Servers/1/password']) ? '' : $values['Servers/1/password']);
             $test = static::testDBConnection(
-                $values['Servers/1/connect_type'],
-                $values['Servers/1/host'],
-                $values['Servers/1/port'],
-                $values['Servers/1/socket'],
-                $values['Servers/1/user'],
+                empty($values['Servers/1/connect_type']) ? '' : $values['Servers/1/connect_type'],
+                empty($values['Servers/1/host']) ? '' : $values['Servers/1/host'],
+                empty($values['Servers/1/port']) ? '' : $values['Servers/1/port'],
+                empty($values['Servers/1/socket']) ? '' : $values['Servers/1/socket'],
+                empty($values['Servers/1/user']) ? '' : $values['Servers/1/user'],
                 $password,
                 'Server'
             );
@@ -345,19 +351,19 @@
         );
         $error = false;
 
-        if ($values['Servers/1/pmadb'] == '') {
+        if (empty($values['Servers/1/pmadb'])) {
             return $result;
         }
 
         $result = array();
-        if ($values['Servers/1/controluser'] == '') {
+        if (empty($values['Servers/1/controluser'])) {
             $result['Servers/1/controluser'] = __(
                 'Empty phpMyAdmin control user while using phpMyAdmin configuration '
                 . 'storage!'
             );
             $error = true;
         }
-        if ($values['Servers/1/controlpass'] == '') {
+        if (empty($values['Servers/1/controlpass'])) {
             $result['Servers/1/controlpass'] = __(
                 'Empty phpMyAdmin control user password while using phpMyAdmin '
                 . 'configuration storage!'
@@ -366,10 +372,13 @@
         }
         if (! $error) {
             $test = static::testDBConnection(
-                $values['Servers/1/connect_type'],
-                $values['Servers/1/host'], $values['Servers/1/port'],
-                $values['Servers/1/socket'], $values['Servers/1/controluser'],
-                $values['Servers/1/controlpass'], 'Server_pmadb'
+                empty($values['Servers/1/connect_type']) ? '' : $values['Servers/1/connect_type'],
+                empty($values['Servers/1/host']) ? '' : $values['Servers/1/host'],
+                empty($values['Servers/1/port']) ? '' : $values['Servers/1/port'],
+                empty($values['Servers/1/socket']) ? '' : $values['Servers/1/socket'],
+                empty($values['Servers/1/controluser']) ? '' : $values['Servers/1/controluser'],
+                empty($values['Servers/1/controlpass']) ? '' : $values['Servers/1/controlpass'],
+                'Server_pmadb'
             );
             if ($test !== true) {
                 $result = array_merge($result, $test);
@@ -391,7 +400,7 @@
     {
         $result = array($path => '');
 
-        if ($values[$path] == '') {
+        if (empty($values[$path])) {
             return $result;
         }
 
@@ -400,7 +409,7 @@
         $matches = array();
         // in libraries/ListDatabase.php _checkHideDatabase(),
         // a '/' is used as the delimiter for hide_db
-        preg_match('/' . $values[$path] . '/', '', $matches);
+        preg_match('/' . Util::requestString($values[$path]) . '/', '', $matches);
 
         static::testPHPErrorMsg(false);
 
@@ -428,10 +437,11 @@
             return $result;
         }
 
-        if (is_array($values[$path])) {
+        if (is_array($values[$path]) || is_object($values[$path])) {
             // value already processed by FormDisplay::save
             $lines = array();
             foreach ($values[$path] as $ip => $v) {
+                $v = Util::requestString($v);
                 $lines[] = preg_match('/^-\d+$/', $ip)
                     ? $v
                     : $ip . ': ' . $v;
@@ -483,14 +493,16 @@
         $max_value,
         $error_string
     ) {
-        if ($values[$path] === '') {
+        if (empty($values[$path])) {
             return '';
         }
 
-        if (intval($values[$path]) != $values[$path]
-            || (! $allow_neg && $values[$path] < 0)
-            || (! $allow_zero && $values[$path] == 0)
-            || $values[$path] > $max_value
+        $value = Util::requestString($values[$path]);
+
+        if (intval($value) != $value
+            || (! $allow_neg && $value < 0)
+            || (! $allow_zero && $value == 0)
+            || $value > $max_value
         ) {
             return $error_string;
         }
@@ -576,7 +588,10 @@
      */
     public static function validateByRegex($path, $values, $regex)
     {
-        $result = preg_match($regex, $values[$path]);
+        if (!isset($values[$path])) {
+            return '';
+        }
+        $result = preg_match($regex, Util::requestString($values[$path]));
         return array($path => ($result ? '' : __('Incorrect value!')));
     }
 
```
