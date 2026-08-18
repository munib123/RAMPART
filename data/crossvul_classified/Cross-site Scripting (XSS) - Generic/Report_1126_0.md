# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1126_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1126_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 72-112 of the vulnerable file.

				mwexec("/sbin/ipfw {$g['tmp_path']}/passthrumac_gui");
				@unlink("{$g['tmp_path']}/passthrumac_gui");
			}
			if ($retval == 0) {
				clear_subsystem_dirty('passthrumac');
			}
		}
	}

	if ($_POST['postafterlogin']) {
		if (empty($a_passthrumacs)) {
			echo gettext("No entry exists yet!") ."\n";
			exit;
		}

		if ($_POST['username']) {
			$mac = captiveportal_passthrumac_findbyname($_POST['username']);
			if (!empty($mac)) {
				$_POST['delmac'] = $mac['mac'];
			} else {
				echo gettext("No entry exists for this username:") . " " . $_POST['username'] . "\n";
			}
		}

		if ($_POST['delmac']) {
			$found = false;
			foreach ($a_passthrumacs as $idx => $macent) {
				if ($macent['mac'] == $_POST['delmac']) {
					$found = true;
					break;
				}
			}
			if ($found == true) {
				$cpzoneid = $a_cp[$cpzone]['zoneid'];
				$rules = captiveportal_passthrumac_delete_entry($a_passthrumacs[$idx]);
				$uniqid = uniqid("{$cpzone}_mac");
				file_put_contents("{$g['tmp_path']}/{$uniqid}_tmp", $rules);
				mwexec("/sbin/ipfw -q {$g['tmp_path']}/{$uniqid}_tmp");
				@unlink("{$g['tmp_path']}/{$uniqid}_tmp");
				unset($a_passthrumacs[$idx]);
				write_config();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,7 +89,7 @@
 			if (!empty($mac)) {
 				$_POST['delmac'] = $mac['mac'];
 			} else {
-				echo gettext("No entry exists for this username:") . " " . $_POST['username'] . "\n";
+				echo gettext("No entry exists for this username:") . " " . htmlspecialchars($_POST['username']) . "\n";
 			}
 		}
 
@@ -112,7 +112,7 @@
 				write_config();
 				echo gettext("The entry was successfully deleted") . "\n";
 			} else {
-				echo gettext("No entry exists for this mac address:") . " " . $_POST['delmac'] . "\n";
+				echo gettext("No entry exists for this mac address:") . " " . htmlspecialchars($_POST['delmac']) . "\n";
 			}
 		}
 		exit;
```
