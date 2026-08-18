# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2176_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2176_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php
// ENGLISH
if (!isset($_SESSION['settings']['cpassman_url'])) {
    $TeamPass_url = '';
} else {
    $TeamPass_url = $_SESSION['settings']['cpassman_url'];
}

$txt['url_copied_clipboard'] = "URL copied in clipboard";
$txt['url_copy'] = "Copy URL in clipboard";

$txt['settings_attachments_encryption'] = "Enable encryption of Items attachments";
$txt['settings_attachments_encryption_tip'] = "THIS OPTION COULD BREAK EXISTING ATTACHMENTS, please read carefully the next. If enabled, Items attachments are stored encrypted on the server. The ecryption uses the SALT defined for Teampass. This requieres more server ressources. WARNING: once you change strategy, it is mandatory to run the script to adapt existing attachments. See tab 'Specific Actions'.";
$txt['admin_action_attachments_cryption'] = "Encrypt or Decrypt the Items attachments";
$txt['admin_action_attachments_cryption_tip'] = "WARNING: this action has ONLY to be performed after changing the associated option in Teampass settings. Please make a copy of the folder 'upload' before doing any action, just in case ...";
$txt['encrypt'] = "Encrypt";
$txt['decrypt'] = "Decrypt";

$txt['user_ga_code'] = "Send GoogleAuthenticator to user by email";
$txt['send_ga_code'] = "Google Authenticator for user";
$txt['error_no_email'] = "This user has no email set!";
$txt['error_no_user'] = "No user found!";
$txt['email_ga_subject'] = "Your Google Authenticator flash code for Teampass";
$txt['email_ga_text'] = "Hello,<br><br>Please click this <a href='#link#'>LINK</a> and flash it with GoogleAuthenticator application to get your OTP credentials for Teampass.<br /><br />Cheers";

$txt['admin_ga_website_name'] = "Name displayed Google Authenticator for Teampass";
$txt['admin_ga_website_name_tip'] = "This name is used for the identification code account in Google Authenticator.";
$txt['admin_action_pw_prefix_correct'] = "Correct passwords prefix";
$txt['admin_action_pw_prefix_correct_tip'] = "Before lauching this script, PLEASE be sure to make a dump of the database. This script will perform an update of passwords prefix. It SHALL only be used if you noticed that passwords are displayed with strange prefix.";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,8 @@
     $TeamPass_url = $_SESSION['settings']['cpassman_url'];
 }
 
+$txt['one_time_item_view'] = "One time view link";
+$txt['one_time_view_item_url_box'] = "Share the One-Time URL with a person of Trust <br><br>#URL#<br><br>Remember that this link will only be visible one time until the #DAY#";
 $txt['url_copied_clipboard'] = "URL copied in clipboard";
 $txt['url_copy'] = "Copy URL in clipboard";
 
```
