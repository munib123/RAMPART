# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5548_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5548_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php

/**
 * Elgg twitter view page
 *
 * @package ElggTwitter
 */

//some required params

$username = $vars['entity']->twitter_username;
$num = $vars['entity']->twitter_num;

// if the twitter username is empty, then do not show
if ($username) {

?>

<div id="twitter_widget">
	<ul id="twitter_update_list"></ul>
	<p class="visit_twitter"><a href="http://twitter.com/<?php echo $username; ?>"><?php echo elgg_echo("twitter:visit"); ?></a></p>
	<script type="text/javascript" src="http://twitter.com/javascripts/blogger.js"></script>
	<script type="text/javascript" src="http://twitter.com/statuses/user_timeline/<?php echo $username; ?>.json?callback=twitterCallback2&count=<?php echo $num; ?>"></script>
</div>

<?php
} else {

	echo "<div class=\"contentWrapper\"><p>" . elgg_echo("twitter:notset") . ".</p></div>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,26 +6,39 @@
  * @package ElggTwitter
  */
 
-//some required params
+$username = $vars['entity']->twitter_username;
 
-$username = $vars['entity']->twitter_username;
+if (empty($username)) {
+	echo "<div class=\"contentWrapper\"><p>" . elgg_echo("twitter:notset") . "</p></div>";
+	return;
+}
+
+$username_is_valid = preg_match('~^[a-zA-Z0-9_]{1,20}$~', $username);
+
+if (!$username_is_valid) {
+	echo "<div class=\"contentWrapper\"><p>" . elgg_echo("twitter:invalid") . "</p></div>";
+	return;
+}
+
+
+
 $num = $vars['entity']->twitter_num;
+if (empty($num)) {
+	$num = 5;
+}
 
-// if the twitter username is empty, then do not show
-if ($username) {
+// @todo upgrade to 1.1 API https://dev.twitter.com/docs/api/1.1/get/statuses/home_timeline
+$script_url = "https://api.twitter.com/1/statuses/user_timeline/" . urlencode($username) . ".json"
+	. "?callback=twitterCallback2&count=" . (int) $num;
 
 ?>
-
 <div id="twitter_widget">
 	<ul id="twitter_update_list"></ul>
-	<p class="visit_twitter"><a href="http://twitter.com/<?php echo $username; ?>"><?php echo elgg_echo("twitter:visit"); ?></a></p>
+	<p class="visit_twitter"><?php echo elgg_view('output/url', array(
+		'text' => elgg_echo("twitter:visit"),
+		'href' => 'http://twitter.com/' . urlencode($username),
+		'is_trusted' => true,
+	)) ?></p>
 	<script type="text/javascript" src="http://twitter.com/javascripts/blogger.js"></script>
-	<script type="text/javascript" src="http://twitter.com/statuses/user_timeline/<?php echo $username; ?>.json?callback=twitterCallback2&count=<?php echo $num; ?>"></script>
+	<script type="text/javascript" src="<?php echo htmlspecialchars($script_url, ENT_QUOTES, 'UTF-8') ?>"></script>
 </div>
-
-<?php
-} else {
-
-	echo "<div class=\"contentWrapper\"><p>" . elgg_echo("twitter:notset") . ".</p></div>";
-
-}
```
