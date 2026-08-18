# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 3601_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3601_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 34-74 of the vulnerable file.

	return file_exists( $t_offline_file );
}

# return user_id if successful, otherwise false.
function mci_check_login( $p_username, $p_password ) {
	if( mci_is_mantis_offline() ) {
		return false;
	}

	# if no user name supplied, then attempt to login as anonymous user.
	if( is_blank( $p_username ) ) {
		$t_anon_allowed = config_get( 'allow_anonymous_login' );
		if( OFF == $t_anon_allowed ) {
			return false;
		}

		$p_username = config_get( 'anonymous_account' );

		# do not use password validation.
		$p_password = null;
	}

	if( false === auth_attempt_script_login( $p_username, $p_password ) ) {
		return false;
	}

	return auth_get_current_user_id();
}

function mci_has_readonly_access( $p_user_id, $p_project_id = ALL_PROJECTS ) {
	$t_access_level = user_get_access_level( $p_user_id, $p_project_id );
	return( $t_access_level >= config_get( 'mc_readonly_access_level_threshold' ) );
}

function mci_has_readwrite_access( $p_user_id, $p_project_id = ALL_PROJECTS ) {
	$t_access_level = user_get_access_level( $p_user_id, $p_project_id );
	return( $t_access_level >= config_get( 'mc_readwrite_access_level_threshold' ) );
}

function mci_has_access( $p_access_level, $p_user_id, $p_project_id = ALL_PROJECTS ) {
	$t_access_level = user_get_access_level( $p_user_id, $p_project_id );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,6 +51,11 @@
 
 		# do not use password validation.
 		$p_password = null;
+	} else {
+		if( is_blank( $p_password ) ) {
+			# require password for authenticated access
+			return false;
+		}
 	}
 
 	if( false === auth_attempt_script_login( $p_username, $p_password ) ) {
```
