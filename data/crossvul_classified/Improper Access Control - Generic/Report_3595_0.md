# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3595_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3595_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 403-444 of the vulnerable file.

	if( $p_user_id === null ) {
		$p_user_id = auth_get_current_user_id();
	}

	# Deal with not logged in silently in this case
	# @@@ we may be able to remove this and just error
	#     and once we default to anon login, we can remove it for sure
	if( empty( $p_user_id ) && !auth_is_user_authenticated() ) {
		return false;
	}

	$t_project_id = bug_get_field( $p_bug_id, 'project_id' );

	# check limit_Reporter (Issue #4769)
	# reporters can view just issues they reported
	$t_limit_reporters = config_get( 'limit_reporters' );
	if(( ON === $t_limit_reporters ) && ( !bug_is_user_reporter( $p_bug_id, $p_user_id ) ) && ( !access_has_project_level( REPORTER + 1, $t_project_id, $p_user_id ) ) ) {
		return false;
	}

	# If the bug is private and the user is not the reporter, then the
	#  the user must also have higher access than private_bug_threshold
	if( VS_PRIVATE == bug_get_field( $p_bug_id, 'view_state' ) && !bug_is_user_reporter( $p_bug_id, $p_user_id ) ) {
		$p_access_level = max( $p_access_level, config_get( 'private_bug_threshold' ) );
	}

	return access_has_project_level( $p_access_level, $t_project_id, $p_user_id );
}

/**
 * Check if the user has the specified access level for the given bug
 * and deny access to the page if not
 * @see access_has_bug_level
 * @param int $p_access_level integer representing access level
 * @param int $p_bug_id integer representing bug id to check access against
 * @param int|null $p_user_id integer representing user id, defaults to null to use current user
 * @return bool whether user has access level specified
 * @access public
 */
function access_ensure_bug_level( $p_access_level, $p_bug_id, $p_user_id = null ) {
	if( !access_has_bug_level( $p_access_level, $p_bug_id, $p_user_id ) ) {
		access_denied();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -420,10 +420,12 @@
 		return false;
 	}
 
-	# If the bug is private and the user is not the reporter, then the
-	#  the user must also have higher access than private_bug_threshold
+	# If the bug is private and the user is not the reporter, then
+	# they must also have higher access than private_bug_threshold
 	if( VS_PRIVATE == bug_get_field( $p_bug_id, 'view_state' ) && !bug_is_user_reporter( $p_bug_id, $p_user_id ) ) {
-		$p_access_level = max( $p_access_level, config_get( 'private_bug_threshold' ) );
+		$t_access_level = access_get_project_level( $t_project_id, $p_user_id );
+		return access_compare_level( $t_access_level, config_get( 'private_bug_threshold' ) )
+		    && access_compare_level( $t_access_level, $p_access_level );
 	}
 
 	return access_has_project_level( $p_access_level, $t_project_id, $p_user_id );
```
