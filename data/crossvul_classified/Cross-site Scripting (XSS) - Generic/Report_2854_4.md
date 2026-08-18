# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php 
/**
 *
 * @file          bulgarian.php
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
    'text' => 'Text',
    'masked' => 'Masked',
    'type' => 'Type',
    'select_type_of_field' => 'Select type of field',
    'define_new_field' => 'Define new field',
    'data_is_text' => 'Data is Text',
    'data_is_masked' => 'Data is Hidden',
    'at_export' => 'Export',
    'setting_disabled_by_admin' => 'This setting is disabled by Administrator',
    'confirm_change_field_type' => 'Confirm changing the field type',
    'user_ga_code' => 'Изптати Google Authenticator на потребителя по имейл',
    'send_ga_code' => 'Google Authenticator за потребител',
    'error_no_email' => 'Този потребител няма настроен имейл!',
    'error_no_user' => 'Потребителят не е намерен!',
    'email_ga_subject' => 'Вашият Google Authenticator флаш код за Teampass',
    'email_ga_text' => 'Здравейте,<br><b',
    'settings_attachments_encryption' => 'Активиране на криптация на прикачени файлове',
    'settings_attachments_encryption_tip' => 'ТАЗИ ОПЦИЯ ПОЖЕ ДА ПОВРЕДИ СЪЩЕСТВУВАЩИТЕ ПРИКАЧЕНИ ФАЙЛОВЕ, прочетете внимателно следващия текс. Ако е тази опция е активиерана, прикачените файлове се съхраняват на сървъра в криптиран вид. Криптацията използва SALT ключът дефиниран за Teampass. Това  изисква повече сървърни ресурси. WARNING: ако веднъж промените стратегията си, е задължително да пуснете скрипта за адаптиране на съществуващите прикачени файлове. Вижте раздек \'Спесифични действия\'.',
    'admin_action_attachments_cryption' => 'Криптирай или декриптирай прикачените файлове',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
  */
 global $LANG;
 $LANG = array (
+    'access_level_for_roles' => 'Associated access for Roles',
     'admin_script_backup_secret' => 'Passkey for backup execution',
     'admin_script_backup_secret_tip' => 'The backup passkey needs to be provided to start the backup. It has to be added a key parameter to script.backup.php. Example:scripts.backup.php?key=your_passkey',
     'text' => 'Text',
```
