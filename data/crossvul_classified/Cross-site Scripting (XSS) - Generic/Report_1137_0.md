# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1137_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1137_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 31-90 of the vulnerable file.


//check permissions
	if (permission_exists('system_status_sofia_status')
		|| permission_exists('system_status_sofia_status_profile')
		|| if_group("superadmin")) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//define variables
	$c = 0;
	$row_style["0"] = "row_style0";
	$row_style["1"] = "row_style1";

if ($_GET['a'] == "download") {
	if ($_GET['t'] == "cdrcsv") {
		$tmp = $_SESSION['switch']['log']['dir'].'/cdr-csv/';
		$filename = 'Master.csv';
	}
	if ($_GET['t'] == "backup") {
		$tmp = $backup_dir.'/';
		$filename = 'backup.tgz';
		if (!is_dir($backup_dir.'/')) {
			exec("mkdir ".$backup_dir."/");
		}
		$parent_dir = realpath($_SESSION['switch']['base']['dir']."/..");
		chdir($parent_dir);
		shell_exec('tar cvzf freeswitch '.$backup_dir.'/backup.tgz');
	}
	session_cache_limiter('public');
	$fd = fopen($tmp.$filename, "rb");
	header("Content-Type: binary/octet-stream");
	header("Content-Length: " . filesize($tmp.$filename));
	header('Content-Disposition: attachment; filename="'.$filename.'"');
	fpassthru($fd);
	exit;
}

//show the content
	require_once "resources/header.php";
	$document['title'] = $text['title-sip-status'];

	$msg = $_GET["savemsg"];
	if ($_SESSION['event_socket_ip_address'] == "0.0.0.0") {
		$socket_ip = '127.0.0.1';
		$fp = event_socket_create($socket_ip, $_SESSION['event_socket_port'], $_SESSION['event_socket_password']);
	} else {
		$fp = event_socket_create($_SESSION['event_socket_ip_address'], $_SESSION['event_socket_port'], $_SESSION['event_socket_password']);
	}
	if (!$fp) {
		$msg = "<div align='center'>".$text['error-event-socket']."<br /></div>";
	}
	if (strlen($msg) > 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,30 +48,6 @@
 	$c = 0;
 	$row_style["0"] = "row_style0";
 	$row_style["1"] = "row_style1";
-
-if ($_GET['a'] == "download") {
-	if ($_GET['t'] == "cdrcsv") {
-		$tmp = $_SESSION['switch']['log']['dir'].'/cdr-csv/';
-		$filename = 'Master.csv';
-	}
-	if ($_GET['t'] == "backup") {
-		$tmp = $backup_dir.'/';
-		$filename = 'backup.tgz';
-		if (!is_dir($backup_dir.'/')) {
-			exec("mkdir ".$backup_dir."/");
-		}
-		$parent_dir = realpath($_SESSION['switch']['base']['dir']."/..");
-		chdir($parent_dir);
-		shell_exec('tar cvzf freeswitch '.$backup_dir.'/backup.tgz');
-	}
-	session_cache_limiter('public');
-	$fd = fopen($tmp.$filename, "rb");
-	header("Content-Type: binary/octet-stream");
-	header("Content-Length: " . filesize($tmp.$filename));
-	header('Content-Disposition: attachment; filename="'.$filename.'"');
-	fpassthru($fd);
-	exit;
-}
 
 //show the content
 	require_once "resources/header.php";
```
