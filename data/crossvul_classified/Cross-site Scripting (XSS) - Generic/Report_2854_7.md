# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php 
/**
 *
 * @file          czech.php
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
    'user_ga_code' => 'Zaslat uživateli Google Authenticator emailem',
    'send_ga_code' => 'Google Authenticator pro uživatele',
    'error_no_email' => 'Tento uživatel nemá nastavenou emailovou adresu!',
    'error_no_user' => 'Uživatel nebyl nalezen!',
    'email_ga_subject' => 'Váš snímatelný kód Google Authenticator pro Teampass',
    'email_ga_text' => 'Dobrý den,<br><br>Prosím klikněte na tento <a href=\'#link#\'>LINK</a> and sejměte jej Vaší aplikací GoogleAuthenticator. Tím získáte Vaše jednorázové autorizační údaje pro Teampass.<br /><br />Na shledanou',
    'settings_attachments_encryption' => 'Dovolit šifrování příloh položek',
    'settings_attachments_encryption_tip' => 'TATO VOLBA MŮŽE POŠKODIT STÁVAJÍCÍ PŘÍLOHY - prosím čtěte pečlivě následující informace. Je-li tato volba aktivována, jsou přílohy položek uloženy zašifrované na serveru. Pro šifrování je užíván klíč SALT, definovaný pro Teampass. Tato procedura vyžaduje na serveru více zdrojů. POZOR: rozhodnete-li se pro toto nastavení, je třeba spustit skript pro konverzi stávajících příloh. Viz záložka \'Zvláštní akce\'.',
    'admin_action_attachments_cryption' => 'Zašifrovat nebo odšifrovat přílohy položek.',
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
