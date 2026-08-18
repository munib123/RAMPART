# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1701_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1701_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 39-64 of the vulnerable file.

			'type' => 'textarea',
			'class' => 'form-control span6',
			'placeholder' => 'A description of the template'
		));
		echo $this->Form->input('share', array(
			'label' => 'Share this template with others',
		));
	?>
	</fieldset>
<?php echo $this->Form->button(__('Create'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'templates', 'menuItem' => 'add'));
?>
<script type="text/javascript">
var selectedTags = [];
var allTags = [
	<?php 
		foreach ($tagInfo as $tag) {
			echo "{'id' : '" . $tag['Tags']['id'] . "', 'name' : '" . $tag['Tags']['name'] . "', 'colour' : '" . $tag['Tags']['colour'] . "'},";
		}
	?>
];
</script>
<?php echo $this->Js->writeBuffer();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,7 @@
 var allTags = [
 	<?php 
 		foreach ($tagInfo as $tag) {
-			echo "{'id' : '" . $tag['Tags']['id'] . "', 'name' : '" . $tag['Tags']['name'] . "', 'colour' : '" . $tag['Tags']['colour'] . "'},";
+			echo "{'id' : '" . h($tag['Tags']['id']) . "', 'name' : '" . h($tag['Tags']['name']) . "', 'colour' : '" . h($tag['Tags']['colour']) . "'},";
 		}
 	?>
 ];
```
