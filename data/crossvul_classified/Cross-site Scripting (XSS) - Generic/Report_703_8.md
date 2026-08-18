# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php

/*
 * Scan subnet for new hosts
 ***************************/

/* functions */
require_once( dirname(__FILE__) . '/../../../functions/functions.php' );

# initialize user object
$Database 	= new Database_PDO;
$User 		= new User ($Database);
$Admin	 	= new Admin ($Database, false);
$Subnets	= new Subnets ($Database);
$Result 	= new Result ();

# verify that user is logged in
$User->check_user_session();


# ID must be numeric
if(!is_numeric($_POST['subnetId']))										{ $Result->show("danger", _("Invalid ID"), true, true); }

# verify that user has write permissionss for subnet
if($Subnets->check_permission ($User->user, $_POST['subnetId']) != 3) 	{ $Result->show("danger", _('You do not have permissions to modify hosts in this subnet')."!", true, true); }

# fetch subnet details
$subnet = $Subnets->fetch_subnet (null, $_POST['subnetId']);
$subnet!==false ? : $Result->show("danger", _("Invalid ID"), true, true);

# IPv6 scanning is not supported
if ( $Subnets->identify_address($subnet->subnet) == "IPv6") 			{ $Result->show("danger", _('IPv6 scanning is not supported').'!', true, true); }

# fix description
$subnet->description = strlen($subnet->description)>0 ? "(".$subnet->description.")" : "";
?>

<!-- header -->
<div class="pHeader"><?php print _('Scan subnet'); ?></div>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,8 @@
 # verify that user is logged in
 $User->check_user_session();
 
+# create csrf token
+$csrf = $User->Crypto->csrf_cookie ("create", "scan");
 
 # ID must be numeric
 if(!is_numeric($_POST['subnetId']))										{ $Result->show("danger", _("Invalid ID"), true, true); }
@@ -104,7 +106,7 @@
 <div class="pFooter">
 	<div class="btn-group">
 		<button class="btn btn-sm btn-default hidePopups"><?php print _('Cancel'); ?></button>
-		<button class="btn btn-sm btn-default btn-success" id="subnetScanSubmit" data-subnetId='<?php print $_POST['subnetId']; ?>'><i class="fa fa-gears"></i> <?php print _('Scan subnet'); ?></button>
+		<button class="btn btn-sm btn-default btn-success" id="subnetScanSubmit" data-subnetId='<?php print $_POST['subnetId']; ?>' data-csrf-cookie='<?php print $csrf; ?>'><i class="fa fa-gears"></i> <?php print _('Scan subnet'); ?></button>
 	</div>
 
 	<div class="subnetTruncateResult"></div>
```
