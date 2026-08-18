# CrossVul Fix Pair: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) in php
**Pair ID:** 3100_0
**Vulnerability Class:** Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
**CWE:** CWE-338
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3100_0`)

## Vulnerability Information & PoC

## Description
Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.

## Vulnerable Code
```php
Lines 652-692 of the vulnerable file.

	return apply_filters( 'wpmu_validate_blog_signup', $result );
}

/**
 * Record site signup information for future activation.
 *
 * @since MU
 *
 * @global wpdb $wpdb WordPress database abstraction object.
 *
 * @param string $domain     The requested domain.
 * @param string $path       The requested path.
 * @param string $title      The requested site title.
 * @param string $user       The user's requested login name.
 * @param string $user_email The user's email address.
 * @param array  $meta       By default, contains the requested privacy setting and lang_id.
 */
function wpmu_signup_blog( $domain, $path, $title, $user, $user_email, $meta = array() )  {
	global $wpdb;

	$key = substr( md5( time() . rand() . $domain ), 0, 16 );
	$meta = serialize($meta);

	$wpdb->insert( $wpdb->signups, array(
		'domain' => $domain,
		'path' => $path,
		'title' => $title,
		'user_login' => $user,
		'user_email' => $user_email,
		'registered' => current_time('mysql', true),
		'activation_key' => $key,
		'meta' => $meta
	) );

	/**
	 * Fires after site signup information has been written to the database.
	 *
	 * @since 4.4.0
	 *
	 * @param string $domain     The requested domain.
	 * @param string $path       The requested path.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -669,7 +669,7 @@
 function wpmu_signup_blog( $domain, $path, $title, $user, $user_email, $meta = array() )  {
 	global $wpdb;
 
-	$key = substr( md5( time() . rand() . $domain ), 0, 16 );
+	$key = substr( md5( time() . wp_rand() . $domain ), 0, 16 );
 	$meta = serialize($meta);
 
 	$wpdb->insert( $wpdb->signups, array(
@@ -719,7 +719,7 @@
 	// Format data
 	$user = preg_replace( '/\s+/', '', sanitize_user( $user, true ) );
 	$user_email = sanitize_email( $user_email );
-	$key = substr( md5( time() . rand() . $user_email ), 0, 16 );
+	$key = substr( md5( time() . wp_rand() . $user_email ), 0, 16 );
 	$meta = serialize($meta);
 
 	$wpdb->insert( $wpdb->signups, array(
```
