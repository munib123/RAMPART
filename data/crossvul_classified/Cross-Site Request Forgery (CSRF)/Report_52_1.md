# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 52_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `52_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); // Date in the past

include_once('./config.inc.php');
include_once('./class/class.U2F.php');

$login = new login($config['database']);
$json = new Services_JSON();
$manager = new manager($config['database']);

$scheme = isset($_SERVER['HTTPS']) ? "https://" : "http://";
$u2f = new u2flib_server\U2F($scheme . $_SERVER['HTTP_HOST']);

try {
	$login->isLoggedIn();
}catch(Exception $ex)
{
	$login->logout();
	header("Location: index.php");
	exit;
}

if(!$login->isLoggedIn())
// THE USER IS NOT LOGGED IN
{
	switch($_GET['p'])
	{
		default:
			include('./templates/header.tpl.php');

			echo '<div id="body">
			<div id="info"><table>
			  <tr>
				<td rowspan="2" width="70"><img id="infoimg" src="./images/info.png" alt="Welcome!" /></td>
				<td><b>Welcome to FreshDNS<span id="infoHead"></span></b></td>
			  </tr>
			  <tr>
				<td rowspan="2">FreshDNS is a webbased, PHP and AJAX powered DNS-administration tool for powerDNS</td>
			  </tr>
			</table></div>
			<div class="leeg">&nbsp;</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,15 @@
 	$login->logout();
 	header("Location: index.php");
 	exit;
+}
+
+if (count($_POST)) {
+	try {
+		$login->xsrfCheck();
+	} catch(Exception $ex) {
+		$json->print_exception($ex);
+		exit;
+	}
 }
 
 if(!$login->isLoggedIn())
```
