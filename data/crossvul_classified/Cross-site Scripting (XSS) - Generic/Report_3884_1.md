# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3884_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3884_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 53-93 of the vulnerable file.

$sourceip = 'any';

if ($_POST || $_REQUEST['host']) {
	unset($input_errors);

	/* input validation */
	$reqdfields = explode(" ", "host ttl");
	$reqdfieldsn = array(gettext("Host"), gettext("ttl"));
	do_input_validation($_REQUEST, $reqdfields, $reqdfieldsn, $input_errors);

	if (($_REQUEST['ttl'] < 1) || ($_REQUEST['ttl'] > MAX_TTL)) {
		$input_errors[] = sprintf(gettext("Maximum number of hops must be between 1 and %s"), MAX_TTL);
	}
	$host = trim($_REQUEST['host']);
	$ipproto = $_REQUEST['ipproto'];
	if (($ipproto == "ipv4") && is_ipaddrv6($host)) {
		$input_errors[] = gettext("When using IPv4, the target host must be an IPv4 address or hostname.");
	}
	if (($ipproto == "ipv6") && is_ipaddrv4($host)) {
		$input_errors[] = gettext("When using IPv6, the target host must be an IPv6 address or hostname.");
	}

	$sourceip = $_REQUEST['sourceip'];
	$ttl = $_REQUEST['ttl'];
	$resolve = $_REQUEST['resolve'];
	$useicmp = $_REQUEST['useicmp'];

	if ($_POST && !$input_errors) {
		$do_traceroute = true;
	}

} else {
	$resolve = false;
	$useicmp = false;
}

if ($input_errors) {
	print_input_errors($input_errors);
}

/* Do the traceroute and show any error */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,6 +70,9 @@
 	}
 	if (($ipproto == "ipv6") && is_ipaddrv4($host)) {
 		$input_errors[] = gettext("When using IPv6, the target host must be an IPv6 address or hostname.");
+	}
+	if (!is_ipaddr($host) && !is_hostname($host)) {
+		$input_errors[] = gettext("Hostname must be a valid hostname or IP address.");
 	}
 
 	$sourceip = $_REQUEST['sourceip'];
@@ -183,7 +186,7 @@
 		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Results')?></h2></div>
 		<div class="panel-body">
 <?php
-	print('<pre>' . $result . '</pre>');
+	print('<pre>' . htmlspecialchars($result) . '</pre>');
 ?>
 		</div>
 	</div>
```
