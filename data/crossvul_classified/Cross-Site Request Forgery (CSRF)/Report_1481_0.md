# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1481_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1481_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

* @ignore
*/
if (!defined('IN_PHPBB'))
{
	exit;
}

/**
* Execute message options
*/
function message_options($id, $mode, $global_privmsgs_rules, $global_rule_conditions)
{
	global $phpbb_root_path, $phpEx, $user, $template, $auth, $config, $db;

	$redirect_url = append_sid("{$phpbb_root_path}ucp.$phpEx", "i=pm&amp;mode=options");

	add_form_key('ucp_pm_options');
	// Change "full folder" setting - what to do if folder is full
	if (isset($_POST['fullfolder']))
	{
		check_form_key('ucp_pm_options', $config['form_token_lifetime'], $redirect_url);
		$full_action = request_var('full_action', 0);

		$set_folder_id = 0;
		switch ($full_action)
		{
			case 1:
				$set_folder_id = FULL_FOLDER_DELETE;
			break;

			case 2:
				$set_folder_id = request_var('full_move_to', PRIVMSGS_INBOX);
			break;

			case 3:
				$set_folder_id = FULL_FOLDER_HOLD;
			break;

			default:
				$full_action = 0;
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,11 @@
 	// Change "full folder" setting - what to do if folder is full
 	if (isset($_POST['fullfolder']))
 	{
-		check_form_key('ucp_pm_options', $config['form_token_lifetime'], $redirect_url);
+		if (!check_form_key('ucp_pm_options'))
+		{
+			trigger_error('FORM_INVALID');
+		}
+
 		$full_action = request_var('full_action', 0);
 
 		$set_folder_id = 0;
```
