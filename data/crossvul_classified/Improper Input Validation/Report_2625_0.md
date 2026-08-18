# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2625_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2625_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 48-88 of the vulnerable file.


		require QA_INCLUDE_DIR.'qa-install.php';

		qa_exit('error');
	}
}


$success = '';
$errorhtml = '';
$suggest = '';
$buttons = array();
$fields = array();
$fielderrors = array();
$hidden = array();


// Process user handling higher up to avoid 'headers already sent' warning

if (!isset($pass_failure_type) && qa_clicked('super')) {
	require_once QA_INCLUDE_DIR.'db/users.php';
	require_once QA_INCLUDE_DIR.'app/users-edit.php';

	$inemail = qa_post_text('email');
	$inpassword = qa_post_text('password');
	$inhandle = qa_post_text('handle');

	$fielderrors = array_merge(
		qa_handle_email_filter($inhandle, $inemail),
		qa_password_validate($inpassword)
	);

	if (empty($fielderrors)) {
		require_once QA_INCLUDE_DIR.'app/users.php';

		$userid = qa_create_new_user($inemail, $inpassword, $inhandle, QA_USER_LEVEL_SUPER);
		qa_set_logged_in_user($userid, $inhandle);

		qa_set_option('feedback_email', $inemail);

		$success .= "Congratulations - Your Question2Answer site is ready to go!\n\nYou are logged in as the super administrator and can start changing settings.\n\nThank you for installing Question2Answer.";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,27 +65,30 @@
 // Process user handling higher up to avoid 'headers already sent' warning
 
 if (!isset($pass_failure_type) && qa_clicked('super')) {
+	require_once QA_INCLUDE_DIR.'db/admin.php';
 	require_once QA_INCLUDE_DIR.'db/users.php';
 	require_once QA_INCLUDE_DIR.'app/users-edit.php';
 
-	$inemail = qa_post_text('email');
-	$inpassword = qa_post_text('password');
-	$inhandle = qa_post_text('handle');
-
-	$fielderrors = array_merge(
-		qa_handle_email_filter($inhandle, $inemail),
-		qa_password_validate($inpassword)
-	);
-
-	if (empty($fielderrors)) {
-		require_once QA_INCLUDE_DIR.'app/users.php';
-
-		$userid = qa_create_new_user($inemail, $inpassword, $inhandle, QA_USER_LEVEL_SUPER);
-		qa_set_logged_in_user($userid, $inhandle);
-
-		qa_set_option('feedback_email', $inemail);
-
-		$success .= "Congratulations - Your Question2Answer site is ready to go!\n\nYou are logged in as the super administrator and can start changing settings.\n\nThank you for installing Question2Answer.";
+	if (qa_db_count_users() == 0) { // prevent creating multiple accounts
+		$inemail = qa_post_text('email');
+		$inpassword = qa_post_text('password');
+		$inhandle = qa_post_text('handle');
+
+		$fielderrors = array_merge(
+			qa_handle_email_filter($inhandle, $inemail),
+			qa_password_validate($inpassword)
+		);
+
+		if (empty($fielderrors)) {
+			require_once QA_INCLUDE_DIR.'app/users.php';
+
+			$userid = qa_create_new_user($inemail, $inpassword, $inhandle, QA_USER_LEVEL_SUPER);
+			qa_set_logged_in_user($userid, $inhandle);
+
+			qa_set_option('feedback_email', $inemail);
+
+			$success .= "Congratulations - Your Question2Answer site is ready to go!\n\nYou are logged in as the super administrator and can start changing settings.\n\nThank you for installing Question2Answer.";
+		}
 	}
 }
 
```
