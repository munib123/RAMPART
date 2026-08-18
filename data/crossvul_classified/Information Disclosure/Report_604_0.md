# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 604_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `604_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 221-261 of the vulnerable file.

 * The $g_anonymous_account user is always considered protected.
 *
 * @access public
 * @return void
 */
function current_user_ensure_unprotected() {
	user_ensure_unprotected( auth_get_current_user_id() );
}

/**
 * Returns the issue filter parameters for the current user
 *
 * @param integer $p_project_id Project id. This argument is only used if a 'filter' string is not passed via the web request.
 *                              The default value is null meaning return the current filter for user's current project
                                if a filter string is not supplied.
 * @return array User filter, if not set, then default filter.
 * @access public
 */
function current_user_get_bug_filter( $p_project_id = null ) {
	$f_filter_string = gpc_get_string( 'filter', '' );
	$t_filter = '';

	if( !is_blank( $f_filter_string ) ) {
		if( is_numeric( $f_filter_string ) ) {
			$t_token = token_get_value( TOKEN_FILTER );
			if( null != $t_token ) {
				$t_filter = json_decode( $t_token, true );
			}
		} else {
			$t_filter = json_decode( $f_filter_string, true );
		}
		$t_filter = filter_ensure_valid_filter( $t_filter );
	} else if( !filter_is_cookie_valid() ) {
		$t_filter = filter_get_default();
	} else {
		$t_user_id = auth_get_current_user_id();
		$t_filter = user_get_bug_filter( $t_user_id, $p_project_id );
	}

	return $t_filter;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -238,7 +238,7 @@
  */
 function current_user_get_bug_filter( $p_project_id = null ) {
 	$f_filter_string = gpc_get_string( 'filter', '' );
-	$t_filter = '';
+	$t_filter = array();
 
 	if( !is_blank( $f_filter_string ) ) {
 		if( is_numeric( $f_filter_string ) ) {
```
