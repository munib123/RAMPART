# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 4846_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4846_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 31-60 of the vulnerable file.

			} elseif (substr($href,0,4) == "http") {
				if (!$admin->urlExists($href)) {
					$integrity_errors[$field] = array("a" => array($href));
				}
			}
		}
	}

	// Only retrieve these if we have errors as we only need them for URL generation
	if (count($integrity_errors)) {
		$action = $admin->getModuleActionForForm($form);
		$module = $admin->getModule($action["module"]);
	}
	
	foreach ($integrity_errors as $field => $error_types) {
		foreach ($error_types as $type => $errors) {
			foreach ($errors as $error) {
?>
<li>
	<section class="integrity_errors">
		<a href="<?=ADMIN_ROOT.$module["route"]."/".$action["route"]."/".$_GET["id"]?>/" target="_blank">Edit</a>
		<span class="icon_small icon_small_warning"></span>
		<p>Broken <?=(($type == "img") ? "Image" : "Link")?>: <?=$error?> in field &ldquo;<?=$form["fields"][$field]["title"]?>&rdquo;</p>
	</section>
</li>
<?
			}
		}
	}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
 ?>
 <li>
 	<section class="integrity_errors">
-		<a href="<?=ADMIN_ROOT.$module["route"]."/".$action["route"]."/".$_GET["id"]?>/" target="_blank">Edit</a>
+		<a href="<?=ADMIN_ROOT.$module["route"]."/".$action["route"]."/".htmlspecialchars($_GET["id"])?>/" target="_blank">Edit</a>
 		<span class="icon_small icon_small_warning"></span>
 		<p>Broken <?=(($type == "img") ? "Image" : "Link")?>: <?=$error?> in field &ldquo;<?=$form["fields"][$field]["title"]?>&rdquo;</p>
 	</section>
```
