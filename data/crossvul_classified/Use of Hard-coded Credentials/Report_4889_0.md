# CrossVul Fix Pair: Use of Hard-coded Credentials in php
**Pair ID:** 4889_0
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4889_0`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```php
Lines 257-297 of the vulnerable file.

		$user_id = email_exists($matcherValue);
	}

	if ($user_id) {
		if (get_option('onelogin_saml_updateuser')) {
			$userdata['ID'] = $user_id;
			unset($userdata['$user_pass']);

			// Prevent to change the role to the superuser (id=1)
			if ($user_id == 1 && isset($userdata['role'])) {
				unset($userdata['role']);
			}

			$user_id = wp_update_user($userdata);
		}
	} else if (get_option('onelogin_saml_autocreate')) {
		if (!validate_username($username)) {
			echo __("The username provided by the IdP"). ' "'. $username. '" '. __("is not valid and can't create the user at wordpress");
			exit();
		}
		$userdata['user_pass'] = '@@@nopass@@@';
		$user_id = wp_insert_user($userdata);
	} else {
		echo __("User provided by the IdP "). ' "'. $matcherValue. '" '. __("does not exist in wordpress and auto-provisioning is disabled.");
		exit();
	}

	if (is_a($user_id, 'WP_Error')) {
		$error = $user_id->get_error_messages();
		echo implode('<br>', $error);
		exit();
	} else if ($user_id) {
		wp_set_current_user($user_id);
		wp_set_auth_cookie($user_id);
		setcookie('saml_login', 1, time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
				#do_action('wp_login', $user_id);
		#wp_signon($user_id);
	}

	if (isset($_REQUEST['RelayState'])) {
		if (!empty($_REQUEST['RelayState']) && (substr($_REQUEST['RelayState'], -strlen('/wp-login.php')) === '/wp-login.php')) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -274,7 +274,7 @@
 			echo __("The username provided by the IdP"). ' "'. $username. '" '. __("is not valid and can't create the user at wordpress");
 			exit();
 		}
-		$userdata['user_pass'] = '@@@nopass@@@';
+		$userdata['user_pass'] = wp_generate_password();
 		$user_id = wp_insert_user($userdata);
 	} else {
 		echo __("User provided by the IdP "). ' "'. $matcherValue. '" '. __("does not exist in wordpress and auto-provisioning is disabled.");
```
