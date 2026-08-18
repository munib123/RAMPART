# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 871_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `871_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 225-265 of the vulnerable file.

			<tr id="fr<?=$certificatename;?>" <?=$display?> onClick="fr_toggle('<?=$certificatename;?>')" ondblclick="document.location='acme_certificates_edit.php?id=<?=$certificatename;?>';" <?=($disabled ? ' class="disabled"' : '')?>>
				<td>
					<input type="checkbox" id="frc<?=$certificatename;?>" onClick="fr_toggle('<?=$certificatename;?>')" name="rule[]" value="<?=$certificatename;?>"/>
					<a class="fa fa-anchor" id="Xmove_<?=$certificatename?>" title="<?=gettext("Move checked entries to here")?>"></a>
				</td>
			  <td>
				<?php
					if ($certificate['status']=='disabled'){
						$iconfn = "disabled";
					} else {
						$iconfn = "enabled";
					}?>
				<a id="btn_<?=$certificatename;?>" href='javascript:togglerow("<?=$certificatename;?>");'>
					<?=acmeicon($iconfn, gettext("click to toggle enable/disable this certificate renewal"))?>
				</a>
			  </td>
			  <td>
				<?=$certificate['name'];?>
			  </td>
			  <td>
				<?=$certificate['desc'];?>
			  </td>
			  <td>
				<?=$certificate['acmeaccount'];?>
			  </td>
			  <td style="white-space: nowrap">
				<?=date('r', $certificate['lastrenewal']);?>
			  </td>
			  <td>
				  <?php
					$method = "";
					if (is_array($certificate['a_domainlist']['item'])) {
						foreach($certificate['a_domainlist']['item'] as $domain) {
							if ($domain['status'] == 'disable') {
								continue;
							}
							$method = $domain['method'];
						}
					}
			
				  if ($method == "dns_manual"): ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -242,10 +242,10 @@
 				<?=$certificate['name'];?>
 			  </td>
 			  <td>
-				<?=$certificate['desc'];?>
+				<?=htmlspecialchars($certificate['desc']);?>
 			  </td>
 			  <td>
-				<?=$certificate['acmeaccount'];?>
+				<?=htmlspecialchars($certificate['acmeaccount']);?>
 			  </td>
 			  <td style="white-space: nowrap">
 				<?=date('r', $certificate['lastrenewal']);?>
```
