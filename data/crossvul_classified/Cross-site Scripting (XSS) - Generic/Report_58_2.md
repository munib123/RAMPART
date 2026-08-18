# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 58_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `58_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.


/**
 *
 * User selfMod check end execute
 *
 */

# include required scripts
require_once( dirname(__FILE__) . '/../../../functions/functions.php' );
require_once (dirname(__FILE__) . "/../../../functions/GoogleAuthenticator/PHPGangsta/GoogleAuthenticator.php");

# initialize required objects
$Database       = new Database_PDO;
$Result         = new Result;
$User           = new User ($Database);
$Admin          = new Admin ($Database, false);
$ga 			= new PHPGangsta_GoogleAuthenticator();

# verify that user is logged in
$User->check_user_session();

# change ?
if(@$_POST['2fa']=="1" && $User->user->{'2fa'}=="1") {
	$Result->show("info", _("No change"), true);
}

# can user change ?
if ($User->settings->{'2fa_userchange'}!="1") {
	$Result->show("danger", _("You are not allowed to change 2fa settings. Please contact system administrator."), true);
}

# init values
$values       = [];
$values['id'] = $User->user->id;

# 2fa and 2fa_secret
if(@$_POST['2fa']=="1") {
	$values['2fa'] = "1";
	# create
	$values['2fa_secret'] = $ga->createSecret($User->settings->{'2fa_length'});
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,9 @@
 
 # verify that user is logged in
 $User->check_user_session();
+
+# validate csrf cookie
+$User->Crypto->csrf_cookie ("validate", "user-menu", $_POST['csrf_cookie']) === false ? $Result->show("danger", _("Invalid CSRF cookie"), true) : "";
 
 # change ?
 if(@$_POST['2fa']=="1" && $User->user->{'2fa'}=="1") {
```
