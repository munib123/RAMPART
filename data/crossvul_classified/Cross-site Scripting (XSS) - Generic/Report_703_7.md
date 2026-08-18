# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 12-36 of the vulnerable file.

$Addresses	= new Addresses ($Database);
$Tools      = new Tools ($Database);
$Result 	= new Result ();

# verify that user is logged in
$User->check_user_session();

# validate csrf cookie
$User->Crypto->csrf_cookie ("validate", "scan", $_POST['csrf_cookie']) === false ? $Result->show("danger", _("Invalid CSRF cookie"), true) : "";


$type = $_POST['type'];

switch ($type) {
    case "scan-icmp":
    case "scan-telnet":
    case "snmp-arp":
    case "snmp-mac":
    case "snmp-route-all":
        $subnet_scan_result_included = true;
        include("subnet-scan-result-$type.php");
        break;
    default:
        $Result->show("danger", _("Invalid scan type"), true);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
     case "snmp-mac":
     case "snmp-route-all":
         $subnet_scan_result_included = true;
-        include("subnet-scan-result-$type.php");
+        require("subnet-scan-result-$type.php");
         break;
     default:
         $Result->show("danger", _("Invalid scan type"), true);
```
