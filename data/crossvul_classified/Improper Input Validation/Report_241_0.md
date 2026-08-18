# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 241_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `241_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1460-1500 of the vulnerable file.

			$location = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}geo_mashup_locations WHERE id = %d", $location_id ) );
			wp_cache_add( $location_id, $location, 'geo_mashup_locations' );
		}
		return self::translate_object( $location, $output );
	}

	/**
	 * Get locations of posts.
	 * 
	 * @since 1.2
	 * @uses GeoMashupDB::get_object_locations()
	 * 
	 * @param string $query_args Same as GeoMashupDB::get_object_locations()
	 * @return array Array of matching rows.
	 */
	public static function get_post_locations( $query_args = '' ) {
		return self::get_object_locations( $query_args );
	}

	/**
	 * Get locations of objects.
	 *
	 * <code>
	 * $results = GeoMashupDB::get_object_locations( array( 
	 * 	'object_name' => 'user', 
	 * 	'minlat' => 30,
	 * 	'maxlat' => 40, 
	 * 	'minlon' => -106, 
	 * 	'maxlat' => -103 ) 
	 * );
	 * </code>
	 * 
	 * @since 1.3
	 *
	 * @param string $query_args Override default args.
	 * @return array Array of matching rows.
	 */
	public static function get_object_locations( $query_args = '' ) {
		global $wpdb;

		$default_args = array( 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1477,6 +1477,61 @@
 	}
 
 	/**
+	 * Sanitize an array of query arguments.
+	 *
+	 * @param array $query_args
+	 *
+	 * @return array
+	 */
+	public static function sanitize_query_args( $query_args ) {
+		array_walk_recursive($query_args, array( __CLASS__, 'sanitize_query_arg' ) );
+		return $query_args;
+	}
+
+	/**
+	 * Sanitize a single query argument.
+	 *
+	 * @param mixed $value May be modified.
+	 * @param string $name
+	 */
+	public static function sanitize_query_arg( &$value, $name ) {
+		switch ($name) {
+			case 'minlat':
+			case 'maxlat':
+			case 'minlng':
+			case 'maxlng':
+			case 'near_lat':
+			case 'near_lng':
+			case 'radius_km':
+			case 'radius_mi':
+				$value = (float) $value;
+				break;
+
+			case 'map_cat':
+			case 'object_ids':
+				$value = preg_replace( '/[^0-9,]', '', $value );
+				break;
+
+			case 'map_post_type':
+			case 'object_name':
+				$value = sanitize_key( $value );
+				break;
+
+			case 'limit':
+			case 'map_offset':
+				$value = (int) $value;
+				break;
+
+			case 'suppress_filters':
+				$value = (bool) $value;
+				break;
+
+			default:
+				$value = sanitize_text_field( $value );
+		}
+	}
+
+	/**
 	 * Get locations of objects.
 	 *
 	 * <code>
```
