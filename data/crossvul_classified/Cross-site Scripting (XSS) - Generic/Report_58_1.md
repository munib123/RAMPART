# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 58_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `58_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 32-72 of the vulnerable file.

<form name="2fa_user" id="2fa_user">
<table id="userModSelf" class="table table-condensed">
<tr>
	<td class="title"><?php print _('2fa status'); ?></td>
	<?php if ($User->settings->{'2fa_userchange'}=="1") { ?>
	<td>
		<input type="checkbox" value="1" class="input-switch" name="2fa" <?php if($User->user->{'2fa'} == 1) print 'checked'; ?>>
	</td>
	<td>
		<input type="submit" class="btn btn-default btn-success btn-sm submit_popup" data-script="app/tools/user-menu/2fa_save.php" data-result_div="userModSelf2faResult" data-form='2fa_user' value="<?php print _("Save"); ?>">
	</td>
	<?php } else { ?>
	<td>
		<?php
		print $User->user->{'2fa'} == 1 ? _("Enabled") : _("Disabled");
		?>
	</td>
	<?php }  ?>
</tr>
</table>
</form>

<!-- result -->
<div id="userModSelf2faResult" style="margin-bottom:90px;display:none"></div>


<hr>
<br><br>
<?php

if($User->user->{'2fa_secret'}!=null) {
	$html   = [];
	$html[] = '<div class="loginForm row" style="width:400px;">';
	$html[] = '		'._('Details for your Google Authenticator are below. Please write down your details, otherwise you will not be able to login to phpipam').".";
	$html[] = '		<div style="border: 2px dashed red;margin:20px;padding: 10px" class="text-center row">';
	$html[] = '			<div class="col-xs-12" style="padding:5px 10px 3px 20px;"><strong>'._('Account').': <span style="color:red; font-size: 16px">'.$username.'</span></strong></div>';
	$html[] = '			<div class="col-xs-12" style="padding:0px 10px 3px 20px;"><strong>'._('Secret').' : <span style="color:red; font-size: 16px">'.$User->user->{'2fa_secret'}.'</span></strong></div>';
	$html[] = '		</div>';
	$html[] = '		<div class="text-center">';
	$html[] = '		<hr>'._('You can also scan followign QR code with Google Authenticator application').':<br><br>';
	$html[] = '			<div id="qrcode" style="width:200px;margin:auto;"></div>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,6 +49,7 @@
 	<?php }  ?>
 </tr>
 </table>
+<input type="hidden" name="csrf_cookie" value="<?php print $csrf; ?>">
 </form>
 
 <!-- result -->
```
