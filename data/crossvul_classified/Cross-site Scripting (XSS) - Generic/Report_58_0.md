# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 58_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `58_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 116-156 of the vulnerable file.

		}
		else {
			print "<span class='text-muted'>No groups</span>";
		}
	}
	?>
	</td>
</tr>
<tr>
	<td><?php print _('Password change required'); ?></td>
	<td><?php print $user->passChange; ?></td>
</tr>



<tr>
	<td colspan="2"><h4><?php print _('Display settings'); ?></h4><hr></td>
</tr>
<tr>
	<td><?php print _('Theme'); ?></td>
	<td><?php print $user->theme=="" ? _("Default") : $user->theme ?></td>
</tr>
<tr>
	<td><?php print _('Compress override'); ?></td>
	<td><?php print $user->compressOverride==1 ? _("Yes") : _("No") ?></td>
</tr>
<tr>
	<td><?php print _('Hide free range'); ?></td>
	<td><?php print $user->hideFreeRange==1 ? _("Yes") : _("No") ?></td>
</tr>
<tr>
	<td><?php print _('Menu type'); ?></td>
	<td><?php print $user->menuType; ?></td>
</tr>



<tr>
	<td colspan="2"><h4><?php print _('Mail settings'); ?></h4><hr></td>
</tr>
<tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,7 +133,7 @@
 </tr>
 <tr>
 	<td><?php print _('Theme'); ?></td>
-	<td><?php print $user->theme=="" ? _("Default") : $user->theme ?></td>
+	<td><?php print $user->theme=="" ? _("Default") : escape_input($user->theme) ?></td>
 </tr>
 <tr>
 	<td><?php print _('Compress override'); ?></td>
```
