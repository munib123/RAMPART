# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 4881_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4881_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 74-115 of the vulnerable file.

	if (get_nfilter_request_var('realm') == 'local') {
		$auth_method = 1;
	}else{
		$auth_method = read_config_option('auth_method');
	}

	switch ($auth_method) {
	case '0':
		/* No auth, no action, also shouldn't get here */
		exit;

		break;
	case '2':
		/* Web Basic Auth */
		$copy_user = true;
		$user_auth = true;
		$realm = 2;
		/* Locate user in database */
		$user = db_fetch_row_prepared('SELECT * FROM user_auth WHERE username = ? AND realm = 2', array($username));

		if (!$user && read_config_option('user_template') == '0') {
			cacti_log("ERROR: User '" . $username . "' authenticated by Web Server, but a Template User is not defined in Cacti.  Exiting.", false, 'AUTH');
			$username = htmlspecialchars($username);
			auth_display_custom_error_message( __('%s authenticated by Web Server, but a Template User is not defined in Cacti.', $username) );
			exit;			
		}

		break;
	case '3':
		/* LDAP Auth */
 		if ((get_nfilter_request_var('realm') == 'ldap') && (strlen(get_nfilter_request_var('login_password')) > 0)) {
			/* include LDAP lib */
			include_once('./lib/ldap.php');

			/* get user DN */
			$ldap_dn_search_response = cacti_ldap_search_dn($username);
			if ($ldap_dn_search_response['error_num'] == '0') {
				$ldap_dn = $ldap_dn_search_response['dn'];
			}else{
				/* Error searching */
				cacti_log('LOGIN: LDAP Error: ' . $ldap_dn_search_response['error_text'], false, 'AUTH');
				$ldap_error = true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,10 +91,10 @@
 		/* Locate user in database */
 		$user = db_fetch_row_prepared('SELECT * FROM user_auth WHERE username = ? AND realm = 2', array($username));
 
-		if (!$user && read_config_option('user_template') == '0') {
-			cacti_log("ERROR: User '" . $username . "' authenticated by Web Server, but a Template User is not defined in Cacti.  Exiting.", false, 'AUTH');
+		if (!$user && read_config_option('user_template') == '0' && read_config_option('guest_user') == '0') {
+			cacti_log("ERROR: User '" . $username . "' authenticated by Web Server, but both Template and Guest Users are not defined in Cacti.  Exiting.", false, 'AUTH');
 			$username = htmlspecialchars($username);
-			auth_display_custom_error_message( __('%s authenticated by Web Server, but a Template User is not defined in Cacti.', $username) );
+			auth_display_custom_error_message( __('%s authenticated by Web Server, but both Template and Guest Users are not defined in Cacti.', $username) );
 			exit;			
 		}
 
```
