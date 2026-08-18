# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1701_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1701_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 46-76 of the vulnerable file.

	?>
	</fieldset>
<?php echo $this->Form->button(__('Edit'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'templates', 'menuItem' => 'edit', 'id' => $id, 'mayModify' => $mayModify));
?>
<script type="text/javascript">
var selectedTags = [
	<?php 
		foreach ($currentTags as $k => $t) {
			if ($k != 0) echo ', ';
			echo '"' . $t['Tag']['name'] . '"';
		}
	?>
];
var allTags = [
	<?php 
		foreach ($tagInfo as $tag) {
			echo "{'id' : '" . $tag['Tags']['id'] . "', 'name' : '" . $tag['Tags']['name'] . "', 'colour' : '" . $tag['Tags']['colour'] . "'},";
		}
	?>
];
$(document).ready( function () {
	for (var i = 0, len = selectedTags.length; i < len; i++) {
		appendTemplateTag(selectedTags[i], 'yes');
	}
});
</script>
<?php echo $this->Js->writeBuffer();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
 var allTags = [
 	<?php 
 		foreach ($tagInfo as $tag) {
-			echo "{'id' : '" . $tag['Tags']['id'] . "', 'name' : '" . $tag['Tags']['name'] . "', 'colour' : '" . $tag['Tags']['colour'] . "'},";
+			echo "{'id' : '" . h($tag['Tags']['id']) . "', 'name' : '" . h($tag['Tags']['name']) . "', 'colour' : '" . h($tag['Tags']['colour']) . "'},";
 		}
 	?>
 ];
```
