# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 921_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `921_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 198-238 of the vulnerable file.

	}

	/**
	 * Record Page in Database
	 */
	public static function record() {
		global $wpdb;

		// Get Current WordPress Page
		$current_page = self::get_page_type();

		// If we didn't find a page id, we don't have anything else to do.
		if ( $current_page['type'] == "unknown" ) {
			return false;
		}

		// Get Page uri
		$page_uri = self::sanitize_page_uri();

		// Check if we have already been to this page today.
		$exist = $wpdb->get_row( "SELECT `page_id` FROM `" . DB::table( 'pages' ) . "` WHERE `date` = '" . TimeZone::getCurrentDate( 'Y-m-d' ) . "' " . ( array_key_exists( "search_query", $current_page ) === true ? "AND `uri` = '" . $page_uri . "'" : "" ) . "AND `type` = '{$current_page['type']}' AND `id` = {$current_page['id']}", ARRAY_A );

		// Update Exist Page
		if ( null !== $exist ) {

			$wpdb->query( $wpdb->prepare( "UPDATE `" . DB::table( 'pages' ) . "` SET `count` = `count` + 1 WHERE `date` = '" . TimeZone::getCurrentDate( 'Y-m-d' ) . "' " . ( array_key_exists( "search_query", $current_page ) === true ? "AND `uri` = '" . $page_uri . "'" : "" ) . "AND `type` = '{$current_page['type']}' AND `id` = %d", $current_page['id'] ) );
			$page_id = $exist['page_id'];

		} else {

			// Prepare Pages Data
			$pages = array(
				'uri'   => $page_uri,
				'date'  => TimeZone::getCurrentDate( 'Y-m-d' ),
				'count' => 1,
				'id'    => $current_page['id'],
				'type'  => $current_page['type']
			);
			$pages = apply_filters( 'wp_statistics_pages_information', $pages );

			// Added to DB
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -215,12 +215,12 @@
 		$page_uri = self::sanitize_page_uri();
 
 		// Check if we have already been to this page today.
-		$exist = $wpdb->get_row( "SELECT `page_id` FROM `" . DB::table( 'pages' ) . "` WHERE `date` = '" . TimeZone::getCurrentDate( 'Y-m-d' ) . "' " . ( array_key_exists( "search_query", $current_page ) === true ? "AND `uri` = '" . $page_uri . "'" : "" ) . "AND `type` = '{$current_page['type']}' AND `id` = {$current_page['id']}", ARRAY_A );
+		$exist = $wpdb->get_row( "SELECT `page_id` FROM `" . DB::table( 'pages' ) . "` WHERE `date` = '" . TimeZone::getCurrentDate( 'Y-m-d' ) . "' " . ( array_key_exists( "search_query", $current_page ) === true ? "AND `uri` = '" . esc_sql( $page_uri ) . "'" : "" ) . "AND `type` = '{$current_page['type']}' AND `id` = {$current_page['id']}", ARRAY_A );
 
 		// Update Exist Page
 		if ( null !== $exist ) {
 
-			$wpdb->query( $wpdb->prepare( "UPDATE `" . DB::table( 'pages' ) . "` SET `count` = `count` + 1 WHERE `date` = '" . TimeZone::getCurrentDate( 'Y-m-d' ) . "' " . ( array_key_exists( "search_query", $current_page ) === true ? "AND `uri` = '" . $page_uri . "'" : "" ) . "AND `type` = '{$current_page['type']}' AND `id` = %d", $current_page['id'] ) );
+			$wpdb->query( $wpdb->prepare( "UPDATE `" . DB::table( 'pages' ) . "` SET `count` = `count` + 1 WHERE `date` = '" . TimeZone::getCurrentDate( 'Y-m-d' ) . "' " . ( array_key_exists( "search_query", $current_page ) === true ? "AND `uri` = '" . esc_sql( $page_uri ) . "'" : "" ) . "AND `type` = '{$current_page['type']}' AND `id` = %d", $current_page['id'] ) );
 			$page_id = $exist['page_id'];
 
 		} else {
```
