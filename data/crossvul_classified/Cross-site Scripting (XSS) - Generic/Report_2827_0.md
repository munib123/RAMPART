# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2827_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2827_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

$title_file = AT_CONTENT_DIR.'feeds/'.$feed_id.'_rss_title.cache';

if (isset($_GET['submit'])) {
	$missing_fields = array();
	//check both fields are not empty
	if (trim($_REQUEST['title']) == '') {
		$missing_fields[] = _AT('title');
	}



	if (trim($_REQUEST['url']) == '') {
		$missing_fields[] = _AT('url');
	}
	if ($missing_fields) {
		$missing_fields = implode(', ', $missing_fields);
		$msg->addError(array('EMPTY_FIELDS', $missing_fields));
	}

	if (!$msg->containsErrors()) {
		$_GET['url'] = $addslashes($_GET['url']);

		$sql	= "REPLACE INTO %sfeeds VALUES(%d, '%s')";
		$result = queryDB($sql, array(TABLE_PREFIX, $feed_id, $_GET['url']));

		//update language
		if ($f = @fopen($title_file, 'w')) {
			fwrite($f, $_GET['title'], strlen($_GET['title']));
			fclose($f);
		}

		//delete old cache file
		@unlink(AT_CONTENT_DIR.'/feeds/'.$feed_id.'_rss.cache');

		$msg->addFeedback('ACTION_COMPLETED_SUCCESSFULLY');
		header('Location: index.php');
		exit;
	} 

} else if (isset($_GET['cancel'])) {
	$msg->addFeedback('CANCELLED');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
 	}
 
 	if (!$msg->containsErrors()) {
-		$_GET['url'] = $addslashes($_GET['url']);
+        $_GET['url'] = htmlspecialchars(strip_tags($_GET['url']), ENT_QUOTES);
 
 		$sql	= "REPLACE INTO %sfeeds VALUES(%d, '%s')";
 		$result = queryDB($sql, array(TABLE_PREFIX, $feed_id, $_GET['url']));
```
