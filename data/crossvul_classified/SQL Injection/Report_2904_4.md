# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2904_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2904_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1089-1129 of the vulnerable file.

	 */
	function _weak_escape( $string ) {
		if ( func_num_args() === 1 && function_exists( '_deprecated_function' ) )
			_deprecated_function( __METHOD__, '3.6.0', 'wpdb::prepare() or esc_sql()' );
		return addslashes( $string );
	}

	/**
	 * Real escape, using mysqli_real_escape_string() or mysql_real_escape_string()
	 *
	 * @see mysqli_real_escape_string()
	 * @see mysql_real_escape_string()
	 * @since 2.8.0
	 *
	 * @param  string $string to escape
	 * @return string escaped
	 */
	function _real_escape( $string ) {
		if ( $this->dbh ) {
			if ( $this->use_mysqli ) {
				return mysqli_real_escape_string( $this->dbh, $string );
			} else {
				return mysql_real_escape_string( $string, $this->dbh );
			}
		}

		$class = get_class( $this );
		if ( function_exists( '__' ) ) {
			/* translators: %s: database access abstraction class, usually wpdb or a class extending wpdb */
			_doing_it_wrong( $class, sprintf( __( '%s must set a database connection for use with escaping.' ), $class ), '3.6.0' );
		} else {
			_doing_it_wrong( $class, sprintf( '%s must set a database connection for use with escaping.', $class ), '3.6.0' );
		}
		return addslashes( $string );
	}

	/**
	 * Escape data. Works on arrays.
	 *
	 * @uses wpdb::_real_escape()
	 * @since  2.8.0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1106,20 +1106,22 @@
 	function _real_escape( $string ) {
 		if ( $this->dbh ) {
 			if ( $this->use_mysqli ) {
-				return mysqli_real_escape_string( $this->dbh, $string );
+				$escaped = mysqli_real_escape_string( $this->dbh, $string );
 			} else {
-				return mysql_real_escape_string( $string, $this->dbh );
-			}
-		}
-
-		$class = get_class( $this );
-		if ( function_exists( '__' ) ) {
-			/* translators: %s: database access abstraction class, usually wpdb or a class extending wpdb */
-			_doing_it_wrong( $class, sprintf( __( '%s must set a database connection for use with escaping.' ), $class ), '3.6.0' );
+				$escaped = mysql_real_escape_string( $string, $this->dbh );
+			}
 		} else {
-			_doing_it_wrong( $class, sprintf( '%s must set a database connection for use with escaping.', $class ), '3.6.0' );
-		}
-		return addslashes( $string );
+			$class = get_class( $this );
+			if ( function_exists( '__' ) ) {
+				/* translators: %s: database access abstraction class, usually wpdb or a class extending wpdb */
+				_doing_it_wrong( $class, sprintf( __( '%s must set a database connection for use with escaping.' ), $class ), '3.6.0' );
+			} else {
+				_doing_it_wrong( $class, sprintf( '%s must set a database connection for use with escaping.', $class ), '3.6.0' );
+			}
+			$escaped = addslashes( $string );
+		}
+
+		return $this->add_placeholder_escape( $escaped );
 	}
 
 	/**
@@ -1201,14 +1203,14 @@
 	 *
 	 * All placeholders MUST be left unquoted in the query string. A corresponding argument MUST be passed for each placeholder.
 	 *
+	 * For compatibility with old behavior, numbered or formatted string placeholders (eg, %1$s, %5s) will not have quotes
+	 * added by this function, so should be passed with appropriate quotes around them for your usage.
+	 *
 	 * Literal percentage signs (%) in the query string must be written as %%. Percentage wildcards (for example,
 	 * to use in LIKE syntax) must be passed via a substitution argument containing the complete LIKE string, these
 	 * cannot be inserted directly in the query string. Also see {@see esc_like()}.
 	 *
-	 * This method DOES NOT support sign, padding, alignment, width or precision specifiers.
-	 * This method DOES NOT support argument numbering or swapping.
-	 *
-	 * Arguments may be passed as individual arguments to the method, or as a single array containing all arguments. A combination 
+	 * Arguments may be passed as individual arguments to the method, or as a single array containing all arguments. A combination
 	 * of the two is not supported.
 	 *
 	 * Examples:
@@ -1225,8 +1227,9 @@
 	 * @return string|void Sanitized query string, if there is a query to prepare.
 	 */
 	public function prepare( $query, $args ) {
-		if ( is_null( $query ) )
+		if ( is_null( $query ) ) {
 			return;
+		}
 
 		// This is not meant to be foolproof -- but it will catch obviously incorrect usage.
 		if ( strpos( $query, '%' ) === false ) {
@@ -1237,8 +1240,10 @@
 		$args = func_get_args();
 		array_shift( $args );
 
-		// If args were passed as an array (as in vsprintf), move them up
+		// If args were passed as an array (as in vsprintf), move them up.
+		$passed_as_array = false;
 		if ( is_array( $args[0] ) && count( $args ) == 1 ) {
+			$passed_as_array = true;
 			$args = $args[0];
 		}
 
@@ -1249,28 +1254,62 @@
 			}
 		}
 
-		$query = str_replace( "'%s'", '%s', $query ); // in case someone mistakenly already singlequoted it
-		$query = str_replace( '"%s"', '%s', $query ); // doublequote unquoting
-		$query = preg_replace( '|(?<!%)%f|' , '%F', $query ); // Force floats to be locale unaware
-		$query = preg_replace( '|(?<!%)%s|', "'%s'", $query ); // quote the strings, avoiding escaped strings like %%s
-		$query = preg_replace( '/%(?:%|$|([^dsF]))/', '%%\\1', $query ); // escape any unescaped percents
-
-		// Count the number of valid placeholders in the query
-		$placeholders = preg_match_all( '/(^|[^%]|(%%)+)%[sdF]/', $query, $matches );
-
-		if ( count ( $args ) !== $placeholders ) {
-			wp_load_translations_early();
-			_doing_it_wrong( 'wpdb::prepare',
-				/* translators: 1: number of placeholders, 2: number of arguments passed */
-				sprintf( __( 'The query does not contain the correct number of placeholders (%1$d) for the number of arguments passed (%2$d).' ),
-					$placeholders,
-					count( $args ) ),
-				'4.9.0'
-			);
+		/*
+		 * Specify the formatting allowed in a placeholder. The following are allowed:
+		 *
+		 * - Sign specifier. eg, $+d
+		 * - Numbered placeholders. eg, %1$s
+		 * - Padding specifier, including custom padding characters. eg, %05s, %'#5s
+		 * - Alignment specifier. eg, %05-s
+		 * - Precision specifier. eg, %.2f
+		 */
+		$allowed_format = '(?:[1-9][0-9]*[$])?[-+0-9]*(?: |0|\'.)?[-+0-9]*(?:\.[0-9]+)?';
+
+		/*
+		 * If a %s placeholder already has quotes around it, removing the existing quotes and re-inserting them
+		 * ensures the quotes are consistent.
+		 *
+		 * For backwards compatibility, this is only applied to %s, and not to placeholders like %1$s, which are frequently
+		 * used in the middle of longer strings, or as table name placeholders.
+		 */
+		$query = str_replace( "'%s'", '%s', $query ); // Strip any existing single quotes.
+		$query = str_replace( '"%s"', '%s', $query ); // Strip any existing double quotes.
+		$query = preg_replace( '/(?<!%)%s/', "'%s'", $query ); // Quote the strings, avoiding escaped strings like %%s.
+
+		$query = preg_replace( "/(?<!%)(%($allowed_format)?f)/" , '%\\2F', $query ); // Force floats to be locale unaware.
+
+		$query = preg_replace( "/%(?:%|$|(?!($allowed_format)?[sdF]))/", '%%\\1', $query ); // Escape any unescaped percents.
+
+		// Count the number of valid placeholders in the query.
+		$placeholders = preg_match_all( "/(^|[^%]|(%%)+)%($allowed_format)?[sdF]/", $query, $matches );
+
+		if ( count( $args ) !== $placeholders ) {
+			if ( 1 === $placeholders && $passed_as_array ) {
+				// If the passed query only expected one argument, but the wrong number of arguments were sent as an array, bail.
+				wp_load_translations_early();
+				_doing_it_wrong( 'wpdb::prepare', __( 'The query only expected one placeholder, but an array of multiple placeholders was sent.' ), '4.9.0' );
+
+				return;
+			} else {
+				/*
+				 * If we don't have the right number of placeholders, but they were passed as individual arguments,
+				 * or we were expecting multiple arguments in an array, throw a warning.
+				 */
+				wp_load_translations_early();
+				_doing_it_wrong( 'wpdb::prepare',
+					/* translators: 1: number of placeholders, 2: number of arguments passed */
+					sprintf( __( 'The query does not contain the correct number of placeholders (%1$d) for the number of arguments passed (%2$d).' ),
+						$placeholders,
+						count( $args ) ),
+					'4.8.3'
+				);
+			}
 		}
 
 		array_walk( $args, array( $this, 'escape_by_ref' ) );
-		return @vsprintf( $query, $args );
+		$query = @vsprintf( $query, $args );
+
+		return $this->add_placeholder_escape( $query );
 	}
 
 	/**
@@ -1891,6 +1930,64 @@
 		if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
 			$this->queries[] = array( $query, $this->timer_stop(), $this->get_caller() );
 		}
+	}
+
+	/**
+	 * Generates and returns a placeholder escape string for use in queries returned by ::prepare().
+	 *
+	 * @since 4.8.3
+	 *
+	 * @return string String to escape placeholders.
+	 */
+	public function placeholder_escape() {
+		static $placeholder;
+
+		if ( ! $placeholder ) {
+			// If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
+			$algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
+			// Old WP installs may not have AUTH_SALT defined.
+			$salt = defined( 'AUTH_SALT' ) ? AUTH_SALT : rand();
+
+			$placeholder = '{' . hash_hmac( $algo, uniqid( $salt, true ), $salt ) . '}';
+		}
+
+		/*
+		 * Add the filter to remove the placeholder escaper. Uses priority 0, so that anything
... (diff truncated)
```
