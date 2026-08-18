# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 879_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `879_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 21-67 of the vulnerable file.

 */

require("guiconfig.inc");
require_once("/usr/local/pkg/apcupsd.inc");

$pgtitle = array(gettext("Package"), gettext("Services: Apcupsd"), gettext("Status"));
include("head.inc");

function puts($arg) {
	echo "$arg\n";
}

$tab_array = array();
$tab_array[] = array(gettext("General"), false, "/pkg_edit.php?xml=apcupsd.xml&amp;id=0");
$tab_array[] = array(gettext("Status"), true, "/apcupsd_status.php");
display_top_tabs($tab_array);

$nis_server = check_nis_running_apcupsd();

if ( $_POST['strapcaccess'] ) {
	puts("<div class=\"panel panel-success responsive\"><div class=\"panel-heading\"><h2 class=\"panel-title\">Status information from apcupsd</h2></div>");
	puts("<pre>");
	puts("Running: apcaccess -h {$_POST['strapcaccess']} <br />");
	putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin");
	$ph = popen("apcaccess -h {$_POST['strapcaccess']} 2>&1", "r" );
	while ($line = fgets($ph)) {
		echo htmlspecialchars($line);
	}
	pclose($ph);
	puts("</pre>");
	puts("</div>");
} elseif ($nis_server) {
	$nisip = (check_nis_ip_apcupsd() != ''? check_nis_ip_apcupsd() : "localhost");
	$nisport = (check_nis_port_apcupsd() != '' ? check_nis_port_apcupsd() : "3551");

	puts("<div class=\"panel panel-success responsive\"><div class=\"panel-heading\"><h2 class=\"panel-title\">Status information from apcupsd</h2></div>");
	puts("<pre>");
	puts("Running: apcaccess -h {$nisip}:{$nisport} <br />");
	putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin");
	$ph = popen("apcaccess -h {$nisip}:{$nisport} 2>&1", "r" );
	while ($line = fgets($ph)) {
		echo htmlspecialchars($line);
	}
	pclose($ph);
	puts("</pre>");
	puts("</div>");
} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,17 +38,21 @@
 $nis_server = check_nis_running_apcupsd();
 
 if ( $_POST['strapcaccess'] ) {
-	puts("<div class=\"panel panel-success responsive\"><div class=\"panel-heading\"><h2 class=\"panel-title\">Status information from apcupsd</h2></div>");
-	puts("<pre>");
-	puts("Running: apcaccess -h {$_POST['strapcaccess']} <br />");
-	putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin");
-	$ph = popen("apcaccess -h {$_POST['strapcaccess']} 2>&1", "r" );
-	while ($line = fgets($ph)) {
-		echo htmlspecialchars($line);
+	if (is_hostname($_POST['strapcaccess'])) {
+		puts("<div class=\"panel panel-success responsive\"><div class=\"panel-heading\"><h2 class=\"panel-title\">Status information from apcupsd</h2></div>");
+		puts("<pre>");
+		puts("Running: apcaccess -h " . htmlspecialchars($_POST['strapcaccess']) . " <br />");
+		putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin");
+		$ph = popen("apcaccess -h " . escapeshellarg($_POST['strapcaccess']) . " 2>&1", "r" );
+		while ($line = fgets($ph)) {
+			echo htmlspecialchars($line);
+		}
+		pclose($ph);
+		puts("</pre>");
+		puts("</div>");
+	} else {
+		print_input_errors(array(gettext("Invalid hostname or IP address")));
 	}
-	pclose($ph);
-	puts("</pre>");
-	puts("</div>");
 } elseif ($nis_server) {
 	$nisip = (check_nis_ip_apcupsd() != ''? check_nis_ip_apcupsd() : "localhost");
 	$nisport = (check_nis_port_apcupsd() != '' ? check_nis_port_apcupsd() : "3551");
```
