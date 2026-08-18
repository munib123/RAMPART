# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3884_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3884_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 50-90 of the vulnerable file.

	unset($input_errors);
	unset($do_ping);

	/* input validation */
	$reqdfields = explode(" ", "host count");
	$reqdfieldsn = array(gettext("Host"), gettext("Count"));
	do_input_validation($_REQUEST, $reqdfields, $reqdfieldsn, $input_errors);
	if (($_REQUEST['count'] < 1) || ($_REQUEST['count'] > MAX_COUNT) || (!is_numericint($_REQUEST['wait']))) {
		$input_errors[] = sprintf(gettext("Count must be between 1 and %s"), MAX_COUNT);
	}	
	if (($_REQUEST['wait'] < 1) || ($_REQUEST['wait'] > MAX_WAIT) || (!is_numericint($_REQUEST['wait']))) {
		$input_errors[] = sprintf(gettext("Wait must be between 1 and %s"), MAX_WAIT);
	}	
	$host = trim($_REQUEST['host']);
	$ipproto = $_REQUEST['ipproto'];
	if (($ipproto == "ipv4") && is_ipaddrv6($host)) {
		$input_errors[] = gettext("When using IPv4, the target host must be an IPv4 address or hostname.");
	}
	if (($ipproto == "ipv6") && is_ipaddrv4($host)) {
		$input_errors[] = gettext("When using IPv6, the target host must be an IPv6 address or hostname.");
	}

	if (!$input_errors) {
		if ($_POST) {
			$do_ping = true;
		}
		if (isset($_REQUEST['sourceip'])) {
			$sourceip = $_REQUEST['sourceip'];
		}
		$count = (empty($_REQUEST['count'])) ? DEFAULT_WAIT : $_REQUEST['count'];
		$wait = (empty($_REQUEST['wait'])) ? DEFAULT_WAIT : $_REQUEST['wait'];
	}
}

if ($do_ping) {
?>
	<script type="text/javascript">
	//<![CDATA[
	window.onload=function() {
		document.getElementById("pingCaptured").wrap='off';
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,9 @@
 	}
 	if (($ipproto == "ipv6") && is_ipaddrv4($host)) {
 		$input_errors[] = gettext("When using IPv6, the target host must be an IPv6 address or hostname.");
+	}
+	if (!is_ipaddr($host) && !is_hostname($host)) {
+		$input_errors[] = gettext("Hostname must be a valid hostname or IP address.");
 	}
 
 	if (!$input_errors) {
@@ -185,7 +188,7 @@
 		</div>
 
 		<div class="panel-body">
-			<pre><?= $result ?></pre>
+			<pre><?= htmlspecialchars($result) ?></pre>
 		</div>
 	</div>
 <?php
```
