# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2854_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2854_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php 
/**
 *
 * @file          chinese.php
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
    'user_ga_code' => '发送 Google 身份验证器至用户，通过电子邮件',
    'send_ga_code' => 'Google 身份验证器，为用户',
    'error_no_email' => '此用户未设置电子邮件地址！',
    'error_no_user' => '未找到用户！',
    'email_ga_subject' => '您的用于 Teampass 的 Google 身份验证器条码',
    'email_ga_text' => '你好，<br><br>请点击此<a href=\'#link#\'>链接</a>刷新 Google 身份验证器应用以获取您用于 Teampass 的一次性凭据。<br /><br />Cheers ',
    'settings_attachments_encryption' => '启用项目附件加密',
    'settings_attachments_encryption_tip' => '此选项可能损坏现有的附件，请仔细阅读下面的内容。项目附件被加密存储在该服务器上。加密是使用为 Teampass 定义的 SALT。这需要更多服务器资源。警告：一旦您更改了策略，它将强制性的运行脚本以适配现有的附件。参见“特殊操作”选项卡。',
    'admin_action_attachments_cryption' => '加密或解密项目附件',
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
