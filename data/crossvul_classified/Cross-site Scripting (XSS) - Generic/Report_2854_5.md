# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php 
/**
 *
 * @file          catalan.php
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
    'user_ga_code' => 'Envia Google Authenticator per email a l\'usuari',
    'send_ga_code' => 'Estableix i envia per correu el codi de Google Authenticator',
    'error_no_email' => 'L\'usuari no te email configurat!',
    'error_no_user' => 'No s\'ha trobat l\'usuari!',
    'email_ga_subject' => 'El teu codi flash de Google Authenticator per Teampass',
    'email_ga_text' => 'Si us plau <a href=\'#link#\'>cliqueu aquest enllaç</a> i escanegeu el codi QR amb la vostra aplicació de Google Authenticator per a establir unes credencials d\'un sol us per al gestor de contrasenyes.',
    'settings_attachments_encryption' => 'Habilita xifrat dels ítems adjunts',
    'settings_attachments_encryption_tip' => 'Si s\'activa, els elements adjuntats es xifren al servidor amb la clau de sistema. El xifrat requereix més recursos de servidor. -- Alerta! -- Canviar aquesta opció podria trencar els fitxers d\'adjunts existents! Després de canviar aquesta opció, hauríeu d\'executar la tasca de xifra o desxifra els adjunts existents.',
    'admin_action_attachments_cryption' => 'Xifra o desxifra els adjunts dels ítems ',
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
