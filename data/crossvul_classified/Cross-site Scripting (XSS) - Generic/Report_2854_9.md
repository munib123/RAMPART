# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-21 of the vulnerable file.

<?php 
/**
 *
 * @file          english.php
 * @author        Nils Laumaillé
 * @version       2.1.27
 * @copyright     2009 - 2017 Nils Laumaillé
 * @licensing     GNU AFFERO GPL 3.0
 * @link          http://www.teampass.net
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
global $LANG;
$LANG = array (
    'admin_script_backup_secret' => 'Passkey for backup execution',
    'admin_script_backup_secret_tip' => 'The backup passkey needs to be provided to start the backup. It has to be added a key parameter to script.backup.php. Example:scripts.backup.php?key=your_passkey',
    'user_ga_code' => 'Email Google Authentication to user',
    'send_ga_code' => 'Set and email Google Authentication code',
    'error_no_email' => 'This user has no email address set!',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-<?php 
+<?php
 /**
  *
  * @file          english.php
@@ -14,6 +14,7 @@
  */
 global $LANG;
 $LANG = array (
+    'access_level_for_roles' => 'Associated access for Roles',
     'admin_script_backup_secret' => 'Passkey for backup execution',
     'admin_script_backup_secret_tip' => 'The backup passkey needs to be provided to start the backup. It has to be added a key parameter to script.backup.php. Example:scripts.backup.php?key=your_passkey',
     'user_ga_code' => 'Email Google Authentication to user',
```
