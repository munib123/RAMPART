# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2360_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2360_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 215-255 of the vulnerable file.

 *  If no cookie exists, the user's default project is returned
 * @return int
 */
function helper_get_current_project() {
	global $g_project_override, $g_cache_current_project;

	if( $g_project_override !== null ) {
		return $g_project_override;
	}

	if( $g_cache_current_project === null ) {
		$t_cookie_name = config_get( 'project_cookie' );

		$t_project_id = gpc_get_cookie( $t_cookie_name, null );

		if( null === $t_project_id ) {
			$t_pref = user_pref_get( auth_get_current_user_id(), ALL_PROJECTS, false );
			$t_project_id = $t_pref->default_project;
		} else {
			$t_project_id = explode( ';', $t_project_id );
			$t_project_id = $t_project_id[count( $t_project_id ) - 1];
		}

		if( !project_exists( $t_project_id ) || ( 0 == project_get_field( $t_project_id, 'enabled' ) ) || !access_has_project_level( VIEWER, $t_project_id ) ) {
			$t_project_id = ALL_PROJECTS;
		}
		$g_cache_current_project = (int) $t_project_id;
	}
	return $g_cache_current_project;
}

/**
 * Return the current project id as stored in a cookie, in an Array
 * If no cookie exists, the user's default project is returned
 * If the current project is a subproject, the return value will include
 * any parent projects
 * @return array
 */
function helper_get_current_project_trace() {
	$t_cookie_name = config_get( 'project_cookie' );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -232,13 +232,13 @@
 			$t_project_id = $t_pref->default_project;
 		} else {
 			$t_project_id = explode( ';', $t_project_id );
-			$t_project_id = $t_project_id[count( $t_project_id ) - 1];
+			$t_project_id = (int)$t_project_id[count( $t_project_id ) - 1];
 		}
 
 		if( !project_exists( $t_project_id ) || ( 0 == project_get_field( $t_project_id, 'enabled' ) ) || !access_has_project_level( VIEWER, $t_project_id ) ) {
 			$t_project_id = ALL_PROJECTS;
 		}
-		$g_cache_current_project = (int) $t_project_id;
+		$g_cache_current_project = $t_project_id;
 	}
 	return $g_cache_current_project;
 }
@@ -272,6 +272,9 @@
 
 	} else {
 		$t_project_id = explode( ';', $t_project_id );
+		foreach( $t_project_id as $t_key => $t_id ) {
+			$t_project_id[$t_key] = (int)$t_id;
+		}
 		$t_bottom = $t_project_id[count( $t_project_id ) - 1];
 	}
 
```
