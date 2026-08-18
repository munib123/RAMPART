# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4430_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4430_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1739-1779 of the vulnerable file.

		return true;
	}

	$suppress = $wpdb->suppress_errors();

	/*
	 * Loop over the WP tables. If none exist, then scratch installation is allowed.
	 * If one or more exist, suggest table repair since we got here because the
	 * options table could not be accessed.
	 */
	$wp_tables = $wpdb->tables();
	foreach ( $wp_tables as $table ) {
		// The existence of custom user tables shouldn't suggest an insane state or prevent a clean installation.
		if ( defined( 'CUSTOM_USER_TABLE' ) && CUSTOM_USER_TABLE == $table ) {
			continue;
		}
		if ( defined( 'CUSTOM_USER_META_TABLE' ) && CUSTOM_USER_META_TABLE == $table ) {
			continue;
		}

		if ( ! $wpdb->get_results( "DESCRIBE $table;" ) ) {
			continue;
		}

		// One or more tables exist. We are insane.

		wp_load_translations_early();

		// Die with a DB error.
		$wpdb->error = sprintf(
			/* translators: %s: Database repair URL. */
			__( 'One or more database tables are unavailable. The database may need to be <a href="%s">repaired</a>.' ),
			'maint/repair.php?referrer=is_blog_installed'
		);

		dead_db();
	}

	$wpdb->suppress_errors( $suppress );

	wp_cache_set( 'is_blog_installed', false );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1756,7 +1756,8 @@
 			continue;
 		}
 
-		if ( ! $wpdb->get_results( "DESCRIBE $table;" ) ) {
+		$described_table = $wpdb->get_results( "DESCRIBE $table;" );
+		if ( is_array( $described_table ) && count( $described_table ) === 0 ) {
 			continue;
 		}
 
```
