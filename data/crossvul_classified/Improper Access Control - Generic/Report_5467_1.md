# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5467_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5467_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php
	/** @var array $_ */
	/** @var OC_L10N $l */

style('core', ['styles', 'header']);
?>
<span class="error error-wide">
	<h2><strong><?php p($_['title']) ?></strong></h2>
		<p><?php p($_['message']) ?></p>
	<br>

	<h2><strong><?php p($l->t('Technical details')) ?></strong></h2>
	<ul>
		<li><?php p($l->t('Remote Address: %s', $_['remoteAddr'])) ?></li>
		<li><?php p($l->t('Request ID: %s', $_['requestID'])) ?></li>
		<?php if($_['debugMode']): ?>
			<li><?php p($l->t('Type: %s', $_['errorClass'])) ?></li>
			<li><?php p($l->t('Code: %s', $_['errorCode'])) ?></li>
			<li><?php p($l->t('Message: %s', $_['errorMsg'])) ?></li>
			<li><?php p($l->t('File: %s', $_['file'])) ?></li>
			<li><?php p($l->t('Line: %s', $_['line'])) ?></li>
		<?php endif; ?>
	</ul>

	<?php if($_['debugMode']): ?>
		<br />
		<h2><strong><?php p($l->t('Trace')) ?></strong></h2>
		<pre><?php p($_['trace']) ?></pre>
	<?php endif; ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,6 @@
 ?>
 <span class="error error-wide">
 	<h2><strong><?php p($_['title']) ?></strong></h2>
-		<p><?php p($_['message']) ?></p>
 	<br>
 
 	<h2><strong><?php p($l->t('Technical details')) ?></strong></h2>
```
