# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php 
/**
 *
 * @file          dutch.php
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
    'user_ga_code' => 'E-mail Google Authenticatie naar gebruiker',
    'send_ga_code' => 'Stel Google Authenticatie in en stuur e-mail',
    'error_no_email' => 'Gebruiker heeft geen e-mailadres ingesteld',
    'error_no_user' => 'Gebruiker niet gevonden!',
    'email_ga_subject' => 'Uw One-Time Google Authenticatie code voor Teampass',
    'email_ga_text' => 'Hallo,<br><br>Dit is een automatisch gegenereerde e-mail van de Teampass wachtwoord manager.<br><br>Uw beheerder verwacht dat u Two-Factor authenticatie gebruikt om te in te loggen aan Teampass.<br>Voor de eerste inlog met Two-Factor authenticatie gebruikt u de code die u hieronder in het :"Identificatie code" veld vind:<br><br>----------------------<br>#2FACode#<br>----------------------<br><br>Hierna zal u de gelegenheid gesteld worden om uw One-Time gegevens voor Teampass in te stellen.<br><br>Groeten',
    'settings_attachments_encryption' => 'Versleutel bestandsbijlagen',
    'settings_attachments_encryption_tip' => 'Deze optie kan huidige bijlagen kapot maken, lees de volgende tekst aandachtig door. Als uw bijlage aanstaan, dan zijn deze op de server opgeslagen met encryptie. Deze encryptie gebruikt salt gedefineerd voor Teampass. dit benodigd meer server capaciteit. WAARSCHUWING: Wanneer u van strategie veranderd is het verplicht om het script te draaien dat de bestaande bijlagen aanpast. zie tabblad \'specifieke acties\'.',
    'admin_action_attachments_cryption' => 'Versleutel of ontsleutel alle bestandsbijlagen',
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
