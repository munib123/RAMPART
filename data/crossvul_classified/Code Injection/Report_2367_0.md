# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 2367_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2367_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 186-217 of the vulnerable file.


/**
 * Returns the issue filter parameters for the current user
 *
 * @return Active issue filter for current user or false if no filter is currently defined.
 * @access public
 */
function current_user_get_bug_filter( $p_project_id = null ) {
	$f_filter_string = gpc_get_string( 'filter', '' );
	$t_view_all_cookie = '';
	$t_cookie_detail = '';
	$t_filter = '';

	if( !is_blank( $f_filter_string ) ) {
		if( is_numeric( $f_filter_string ) ) {
			$t_token = token_get_value( TOKEN_FILTER );
			if( null != $t_token ) {
				$t_filter = unserialize( $t_token );
			}
		} else {
			$t_filter = unserialize( $f_filter_string );
		}
	} else if( !filter_is_cookie_valid() ) {
		return false;
	} else {
		$t_user_id = auth_get_current_user_id();
		$t_filter = user_get_bug_filter( $t_user_id, $p_project_id );
	}

	$t_filter = filter_ensure_valid_filter( $t_filter );
	return $t_filter;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,7 +203,7 @@
 				$t_filter = unserialize( $t_token );
 			}
 		} else {
-			$t_filter = unserialize( $f_filter_string );
+			return false;
 		}
 	} else if( !filter_is_cookie_valid() ) {
 		return false;
```
