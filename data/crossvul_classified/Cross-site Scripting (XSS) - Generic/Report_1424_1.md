# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1424_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1424_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 350-390 of the vulnerable file.

						}
						echo haproxyicon("cert", "SSL offloading cert: {$descr}");
					}

					$isadvset = "";
					if ($frontend['advanced_bind']) {
						$isadvset .= "Advanced bind: ".htmlspecialchars($frontend['advanced_bind'])."\r\n";
					}
					if ($frontend['advanced']) {
						$isadvset .= "Advanced pass thru setting used\r\n";
					}
					if ($isadvset) {
						echo haproxyicon("advanced", gettext("Advanced settings set") . ": {$isadvset}");
					}
					?>
				  </td>
				  <td>
					<?=$frontend['name'];?>
				  </td>
				  <td>
					<?=$frontend['desc'];?>
				  </td>
				  <td>
				    <?php
						$first = true;
						foreach($frontend['ipport'] as $addr) {
							//if (!$first)
							//	print "<br/>";
							print "<div style='white-space:nowrap;'>";
							print "{$addr['addr']}:{$addr['port']}";
							if ($addr['ssl'] == 'yes') {
								echo haproxyicon("cert", "SSL offloading");
							}
							print "</div>";
							$first = false;
						}
					?>
				  </td>
				  <td>
				  <?php
					if ($frontend['type'] == 'http') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -367,7 +367,7 @@
 					<?=$frontend['name'];?>
 				  </td>
 				  <td>
-					<?=$frontend['desc'];?>
+					<?=htmlspecialchars($frontend['desc']);?>
 				  </td>
 				  <td>
 				    <?php
@@ -412,7 +412,7 @@
 							echo "<div title='{$hint}'>";
 							echo "<a href='haproxy_pool_edit.php?id={$backend}'>{$backend}</a>";
 							if (!empty($actionitem['acl'])) {
-								echo "&nbsp;if({$actionitem['acl']})";
+								echo "&nbsp;if(" . htmlspecialchars($actionitem['acl']) . ")";
 							}
 							echo "<br/></div>";
 						}
```
