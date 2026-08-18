# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5548_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5548_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-16 of the vulnerable file.

<?php

    /**
	 * Elgg twitter edit page
	 *
	 * @package ElggTwitter
	 */

?>
	<p>
		<?php echo elgg_echo("twitter:username"); ?>
		<input type="text" name="params[twitter_username]" value="<?php echo htmlentities($vars['entity']->twitter_username); ?>" />	
		<br /><?php echo elgg_echo("twitter:num"); ?>
		<input type="text" name="params[twitter_num]" value="<?php echo htmlentities($vars['entity']->twitter_num); ?>" />	
	
	</p>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,9 +8,19 @@
 
 ?>
 	<p>
-		<?php echo elgg_echo("twitter:username"); ?>
-		<input type="text" name="params[twitter_username]" value="<?php echo htmlentities($vars['entity']->twitter_username); ?>" />	
-		<br /><?php echo elgg_echo("twitter:num"); ?>
-		<input type="text" name="params[twitter_num]" value="<?php echo htmlentities($vars['entity']->twitter_num); ?>" />	
-	
+		<label><?php echo elgg_echo("twitter:username"); ?>
+		<?php echo elgg_view('input/text', array(
+			'internalname' => 'params[twitter_username]',
+			'value' => $vars['entity']->twitter_username,
+		)) ?>
+		</label>
 	</p>
+	<p>
+		<label><?php echo elgg_echo("twitter:num"); ?>
+		<?php echo elgg_view('input/text', array(
+			'internalname' => 'params[twitter_num]',
+			'value' => $vars['entity']->twitter_num,
+		)) ?>
+		</label>
+		<small><?php echo elgg_echo("twitter:apibug") ?></small>
+	</p>
```
