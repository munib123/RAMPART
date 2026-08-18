# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2850_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2850_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-24 of the vulnerable file.

<div class="confirmation">
	<?php
		echo $this->Form->create('Sighting', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/sightings/quickDelete/' . $id . '/' . urlencode($rawId) . '/' . $context));
	?>
	<legend>Remove Sighting</legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
	<p>Remove sighting (<?php echo h($id); ?>)?</p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span id="PromptYesButton" role="button" tabindex="0" aria-label="Remove sighting" title="Remove sighting" class="btn btn-primary" onClick="removeSighting('<?php echo h($id); ?>', '<?php echo h($rawId); ?>', '<?php echo h($context); ?>');">Yes</span>
				</td>
				<td style="width:540px;">
				</td>
				<td style="vertical-align:top;">
					<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt(1);">No</span>
				</td>
			</tr>
		</table>
	</div>
	<?php
		echo $this->Form->end();
	?>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
 		<table>
 			<tr>
 				<td style="vertical-align:top">
-					<span id="PromptYesButton" role="button" tabindex="0" aria-label="Remove sighting" title="Remove sighting" class="btn btn-primary" onClick="removeSighting('<?php echo h($id); ?>', '<?php echo h($rawId); ?>', '<?php echo h($context); ?>');">Yes</span>
+					<span id="PromptYesButton" role="button" tabindex="0" aria-label="Remove sighting" title="Remove sighting" class="btn btn-primary" data-id="<?php echo h($id); ?>" data-rawid="<?php echo h($rawId); ?>" data-context="<?php echo h($context); ?>" onClick="removeSighting(this);">Yes</span>
 				</td>
 				<td style="width:540px;">
 				</td>
```
