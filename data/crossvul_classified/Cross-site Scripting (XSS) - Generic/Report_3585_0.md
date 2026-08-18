# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3585_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3585_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 129-170 of the vulnerable file.

	 */
	static function get_page($id, $form = 'Form_EditForm', $uniquenessID = null) {
		$JS_id = (int)$id;
		if($JS_id){
			if(isset($uniquenessID)) {
				self::$rules[$uniquenessID] = "\$('$form').getPageFromServer($JS_id);";	
			} else {
				self::$rules[] = "\$('$form').getPageFromServer($JS_id);";	
			}
		}
	}

	/**
	 * Sets the status-message (overlay-notification in the CMS).
	 * You can call this method multiple times, it will default to the "worst" statusmessage.
	 * 
	 * @param $message string
	 * @param $status string
	 */
	static function status_message($message = "", $status = null) {
		$JS_message = Convert::raw2js($message);
		$JS_status = Convert::raw2js($status);
		if(isset($JS_status)) {
			self::$status_messages[$JS_status] = "statusMessage('{$JS_message}', '{$JS_status}');";
		} else {
			self::$status_messages['unknown'] = "statusMessage('{$JS_message}');";
		}
	}

	/**
	 * Alias for status_message($messsage, 'bad')
	 * 
	 * @param $message string
	 */
	static function error($message = "") {
		$JS_message = Convert::raw2js($message);
		self::$status_messages['bad'] = $JS_message;
	}
	
	/**
	 * Update the status (upper right corner) of the given Form
	 * 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -146,8 +146,8 @@
 	 * @param $status string
 	 */
 	static function status_message($message = "", $status = null) {
-		$JS_message = Convert::raw2js($message);
-		$JS_status = Convert::raw2js($status);
+		$JS_message = Convert::raw2js(Convert::raw2xml($message));
+		$JS_status = Convert::raw2js(Convert::raw2xml($status));
 		if(isset($JS_status)) {
 			self::$status_messages[$JS_status] = "statusMessage('{$JS_message}', '{$JS_status}');";
 		} else {
```
