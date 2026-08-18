# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 7-47 of the vulnerable file.

/* functions */
require_once( dirname(__FILE__) . '/../../../functions/functions.php' );

# initialize user object
$Database 	= new Database_PDO;
$User 		= new User ($Database);
$Tools	 	= new Tools ($Database);
$Admin	 	= new Admin ($Database, false);
$Sections	= new Sections ($Database);
$Subnets	= new Subnets ($Database);
$Addresses	= new Addresses ($Database);
$Scan	 	= new Scan ($Database, $User->settings);
$DNS	 	= new DNS ($Database, $User->settings);
$Result 	= new Result ();

# verify that user is logged in
$User->check_user_session();
# check maintaneance mode
$User->check_maintaneance_mode ();

# subnet Id must be a integer
if(!is_numeric($_POST['subnetId']))	{ $Result->show("danger", _("Invalid ID"), true); }

# verify that user has write permissionss for subnet
if($Subnets->check_permission ($User->user, $_POST['subnetId']) != 3) 	{ $Result->show("danger", _('You do not have permissions to modify hosts in this subnet')."!", true, true); }

# fetch subnet details
$subnet = $Subnets->fetch_subnet (null, $_POST['subnetId']);
$subnet!==false ? : $Result->show("danger", _("Invalid ID"), true, true);

# fake sectionId for snmp-route-all scan
$_POST['sectionId'] = $subnet->sectionId;

# full
if ($_POST['type']!="update-icmp" && $subnet->isFull==1)                { $Result->show("warning", _("Cannot scan as subnet is market as used"), true, true); }

# verify php path
if(!file_exists($Scan->php_exec))	{ $Result->show("danger", _("Invalid php path"), true, true); }

# scan
switch ($_POST['type']) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,9 @@
 # check maintaneance mode
 $User->check_maintaneance_mode ();
 
+# validate csrf cookie
+$User->Crypto->csrf_cookie ("validate", "scan", $_POST['csrf_cookie']) === false ? $Result->show("danger", _("Invalid CSRF cookie"), true) : "";
+
 # subnet Id must be a integer
 if(!is_numeric($_POST['subnetId']))	{ $Result->show("danger", _("Invalid ID"), true); }
 
@@ -43,29 +46,21 @@
 # verify php path
 if(!file_exists($Scan->php_exec))	{ $Result->show("danger", _("Invalid php path"), true, true); }
 
-# scan
-switch ($_POST['type']) {
+$type = $_POST['type'];
+
+switch ($type) {
+#scan
     case "scan-icmp":
-        include("subnet-scan-execute-scan-icmp.php");
-        break;
     case "scan-telnet":
-        include("subnet-scan-execute-scan-telnet.php");
-        break;
     case "snmp-arp":
-        include("subnet-scan-execute-snmp-arp.php");
-        break;
     case "snmp-mac":
-        include("subnet-scan-execute-snmp-mac.php");
-        break;
     case "snmp-route-all":
-        include("subnet-scan-execute-snmp-route-all.php");
-        break;
 # discovery
     case "update-icmp":
-        include("subnet-scan-execute-update-icmp.php");
-        break;
     case "update-snmp-arp":
-        include("subnet-scan-execute-update-snmp-arp.php");
+        $csrf = $_POST['csrf_cookie'];
+        $subnet_scan_execute_included = true;
+        require("subnet-scan-execute-$type.php");
         break;
     default:
         $Result->show("danger", _("Invalid scan type"), true);
```
