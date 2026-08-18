# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3702_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3702_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 207-247 of the vulnerable file.

		// Define error codes for this view.
		define("ER_CODE_VERIFIED", 0);
		define("ER_CODE_NOT_FOUND", 1);
		define("ER_CODE_ALREADY_VERIFIED", 3);

		$code = (isset($_GET['c']) AND !empty($_GET['c'])) ? $_GET['c'] : "";

		$email = (isset($_GET['e']) AND !empty($_GET['e'])) ? $_GET['e'] : "";

		// INITIALIZE the content's section of the view
		$this->template->content = new View('alerts/verify');
		$this->template->header->this_page = 'alerts';

		$filter = " ";
		$missing_info = FALSE;

		if ($_POST AND isset($_POST['alert_code']) AND ! empty($_POST['alert_code']))
		{
			if (isset($_POST['alert_mobile']) AND ! empty($_POST['alert_mobile']))
			{
				$filter = "alert.alert_type=1 AND alert_code='".utf8::strtoupper($_POST['alert_code'])."' AND alert_recipient='".$_POST['alert_mobile']."' ";
			}
			elseif (isset($_POST['alert_email']) AND ! empty($_POST['alert_email']))
			{
				$filter = "alert.alert_type=2 AND alert_code='".$_POST['alert_code']."' AND alert_recipient='".$_POST['alert_email']."' ";
			}
			else
			{
				$missing_info = TRUE;
			}
		}
		else
		{
			if (empty($code) OR empty($email))
			{
				$missing_info = TRUE;
			}
			else
			{
				$filter = "alert.alert_type=2 AND alert_code='".$code."' AND alert_recipient='".$email."' ";
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,11 +224,11 @@
 		{
 			if (isset($_POST['alert_mobile']) AND ! empty($_POST['alert_mobile']))
 			{
-				$filter = "alert.alert_type=1 AND alert_code='".utf8::strtoupper($_POST['alert_code'])."' AND alert_recipient='".$_POST['alert_mobile']."' ";
+				$filter = "alert.alert_type=1 AND alert_code='".Database::instance()->escape_str(utf8::strtoupper($_POST['alert_code']))."' AND alert_recipient='".Database::instance()->escape_str($_POST['alert_mobile'])."' ";
 			}
 			elseif (isset($_POST['alert_email']) AND ! empty($_POST['alert_email']))
 			{
-				$filter = "alert.alert_type=2 AND alert_code='".$_POST['alert_code']."' AND alert_recipient='".$_POST['alert_email']."' ";
+				$filter = "alert.alert_type=2 AND alert_code='".Database::instance()->escape_str($_POST['alert_code'])."' AND alert_recipient='".Database::instance()->escape_str($_POST['alert_email'])."' ";
 			}
 			else
 			{
@@ -243,7 +243,7 @@
 			}
 			else
 			{
-				$filter = "alert.alert_type=2 AND alert_code='".$code."' AND alert_recipient='".$email."' ";
+				$filter = "alert.alert_type=2 AND alert_code='".Database::instance()->escape_str($code)."' AND alert_recipient='".Database::instance()->escape_str($email)."' ";
 			}
 		}
 
```
