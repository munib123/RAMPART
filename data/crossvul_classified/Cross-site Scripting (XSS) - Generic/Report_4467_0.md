# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4467_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4467_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 634-674 of the vulnerable file.

		}

		$body .= '</table>';
		$body .= "\n";
		$backtraceblock->SetBody($body);

		$www['page']->block_add('body',$backtraceblock);
	}

	if ($fatal) {
		$www['page']->display(array('tree'=>false));
		die();
	}
}

/**
 * Return the result of a form variable, with optional default
 *
 * @return The form GET/REQUEST/SESSION/POST variable value or its default
 */
function get_request($attr,$type='POST',$die=false,$default=null,$preventXSS=false) {
	switch($type) {
		case 'GET':
			$value = isset($_GET[$attr]) ? (is_array($_GET[$attr]) ? $_GET[$attr] : (empty($_GET['nodecode'][$attr]) ? rawurldecode($_GET[$attr]) : $_GET[$attr])) : $default;
			break;

		case 'REQUEST':
			$value = isset($_REQUEST[$attr]) ? (is_array($_REQUEST[$attr]) ? $_REQUEST[$attr] : (empty($_REQUEST['nodecode'][$attr]) ? rawurldecode($_REQUEST[$attr]) : $_REQUEST[$attr])) : $default;
			break;

		case 'SESSION':
			$value = isset($_SESSION[$attr]) ? (is_array($_SESSION[$attr]) ? $_SESSION[$attr] : (empty($_SESSION['nodecode'][$attr]) ? rawurldecode($_SESSION[$attr]) : $_SESSION[$attr])) : $default;
			break;

		case 'POST':
		default:
			$value = isset($_POST[$attr]) ? (is_array($_POST[$attr]) ? $_POST[$attr] : (empty($_POST['nodecode'][$attr]) ? rawurldecode($_POST[$attr]) : $_POST[$attr])) : $default;
			break;
	}
	
	if ($die && is_null($value))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -651,7 +651,7 @@
  *
  * @return The form GET/REQUEST/SESSION/POST variable value or its default
  */
-function get_request($attr,$type='POST',$die=false,$default=null,$preventXSS=false) {
+function get_request($attr,$type='POST',$die=false,$default=null,$preventXSS=true) {
 	switch($type) {
 		case 'GET':
 			$value = isset($_GET[$attr]) ? (is_array($_GET[$attr]) ? $_GET[$attr] : (empty($_GET['nodecode'][$attr]) ? rawurldecode($_GET[$attr]) : $_GET[$attr])) : $default;
@@ -675,7 +675,7 @@
 		system_message(array(
 			'title'=>_('Generic Error'),
 			'body'=>sprintf('%s: Called "%s" without "%s" using "%s"',
-				basename($_SERVER['PHP_SELF']),get_request('cmd','REQUEST',false,null,true),preventXSS($attr),preventXSS($type)),
+				basename($_SERVER['PHP_SELF']),get_request('cmd','REQUEST'),preventXSS($attr),preventXSS($type)),
 			'type'=>'error'),
 			'index.php');
 	if($preventXSS && !is_null($value))
@@ -686,10 +686,20 @@
 *  Prevent XSS function. This function can usage has preventXSS(get_request('cmd','REQUEST'))
 *  Return valor escape XSS.
 */
-function preventXSS($value){
-	return htmlspecialchars(addslashes($value), ENT_QUOTES, 'UTF-8');
-}
-
+ function preventXSS($data){
+        if (gettype($data) == 'array') {
+            foreach ($data as $key => $value) {
+                if (gettype($value) == 'array')
+                    $data[$key] = preventXSS($value);
+                else
+                    $data[$key] = htmlspecialchars($value);
+            }
+            return $data;
+        }
+        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
+}
+
+/*
  * Record a system message.
  * This function can be used as an alternative to generate a system message, if page hasnt yet been defined.
  */
```
