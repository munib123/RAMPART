# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 957_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `957_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 58-98 of the vulnerable file.


/**
 * Search entries.
 *
 * @param  array $args Search arguments.
 * @return array
 */
function evf_search_entries( $args ) {
	global $wpdb;

	$args = wp_parse_args(
		$args,
		array(
			'limit'   => 10,
			'offset'  => 0,
			'order'   => 'DESC',
			'orderby' => 'entry_id',
		)
	);

	// Check if form ID is valid for entries.
	if ( ! array_key_exists( $args['form_id'], evf_get_all_forms() ) ) {
		return array();
	}

	$orderby       = isset( $args['orderby'] ) ? sanitize_key( $args['orderby'] ) : 'entry_id';
	$order         = "ORDER BY {$orderby} " . esc_sql( strtoupper( $args['order'] ) );
	$limit         = -1 < $args['limit'] ? $wpdb->prepare( 'LIMIT %d', $args['limit'] ) : '';
	$offset        = 0 < $args['offset'] ? $wpdb->prepare( 'OFFSET %d', $args['offset'] ) : '';
	$status        = ! empty( $args['status'] ) ? "AND `status` = '" . sanitize_key( $args['status'] ) . "'" : '';
	$search        = ! empty( $args['search'] ) ? "AND `meta_value` LIKE '%" . $wpdb->esc_like( sanitize_text_field( $args['search'] ) ) . "%'" : '';
	$include       = ! empty( $args['form_id'] ) ? "AND `form_id` = '" . absint( $args['form_id'] ) . "'" : '';
	$exclude       = '';
	$date_created  = '';
	$date_modified = '';

	if ( ! empty( $args['after'] ) || ! empty( $args['before'] ) ) {
		$args['after']  = empty( $args['after'] ) ? '0000-00-00' : $args['after'];
		$args['before'] = empty( $args['before'] ) ? current_time( 'mysql', 1 ) : $args['before'];

		$date_created = "AND `date_created_gmt` BETWEEN STR_TO_DATE('" . esc_sql( $args['after'] ) . "', '%Y-%m-%d %H:%i:%s') and STR_TO_DATE('" . esc_sql( $args['before'] ) . "', '%Y-%m-%d %H:%i:%s')";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,55 +75,45 @@
 		)
 	);
 
+	$statuses     = array_keys( evf_get_entry_statuses() );
+	$valid_fields = array( 'date', 'form_id', 'title', 'status' );
+
 	// Check if form ID is valid for entries.
 	if ( ! array_key_exists( $args['form_id'], evf_get_all_forms() ) ) {
 		return array();
 	}
 
-	$orderby       = isset( $args['orderby'] ) ? sanitize_key( $args['orderby'] ) : 'entry_id';
-	$order         = "ORDER BY {$orderby} " . esc_sql( strtoupper( $args['order'] ) );
-	$limit         = -1 < $args['limit'] ? $wpdb->prepare( 'LIMIT %d', $args['limit'] ) : '';
-	$offset        = 0 < $args['offset'] ? $wpdb->prepare( 'OFFSET %d', $args['offset'] ) : '';
-	$status        = ! empty( $args['status'] ) ? "AND `status` = '" . sanitize_key( $args['status'] ) . "'" : '';
-	$search        = ! empty( $args['search'] ) ? "AND `meta_value` LIKE '%" . $wpdb->esc_like( sanitize_text_field( $args['search'] ) ) . "%'" : '';
-	$include       = ! empty( $args['form_id'] ) ? "AND `form_id` = '" . absint( $args['form_id'] ) . "'" : '';
-	$exclude       = '';
-	$date_created  = '';
-	$date_modified = '';
+	$query   = array();
+	$query[] = "SELECT DISTINCT {$wpdb->prefix}evf_entries.entry_id FROM {$wpdb->prefix}evf_entries INNER JOIN {$wpdb->prefix}evf_entrymeta WHERE {$wpdb->prefix}evf_entries.entry_id = {$wpdb->prefix}evf_entrymeta.entry_id";
 
-	if ( ! empty( $args['after'] ) || ! empty( $args['before'] ) ) {
-		$args['after']  = empty( $args['after'] ) ? '0000-00-00' : $args['after'];
-		$args['before'] = empty( $args['before'] ) ? current_time( 'mysql', 1 ) : $args['before'];
-
-		$date_created = "AND `date_created_gmt` BETWEEN STR_TO_DATE('" . esc_sql( $args['after'] ) . "', '%Y-%m-%d %H:%i:%s') and STR_TO_DATE('" . esc_sql( $args['before'] ) . "', '%Y-%m-%d %H:%i:%s')";
+	if ( ! empty( $args['search'] ) ) {
+		$like    = '%' . $wpdb->esc_like( $args['search'] ) . '%';
+		$query[] = $wpdb->prepare( 'AND meta_value LIKE %s', $like );
 	}
 
-	if ( ! empty( $args['modified_after'] ) || ! empty( $args['modified_before'] ) ) {
-		$args['modified_after']  = empty( $args['modified_after'] ) ? '0000-00-00' : $args['modified_after'];
-		$args['modified_before'] = empty( $args['modified_before'] ) ? current_time( 'mysql', 1 ) : $args['modified_before'];
-
-		$date_modified = "AND `date_modified_gmt` BETWEEN STR_TO_DATE('" . esc_sql( $args['modified_after'] ) . "', '%Y-%m-%d %H:%i:%s') and STR_TO_DATE('" . esc_sql( $args['modified_before'] ) . "', '%Y-%m-%d %H:%i:%s')";
+	if ( ! empty( $args['form_id'] ) ) {
+		$query[] = $wpdb->prepare( 'AND form_id = %d', absint( $args['form_id'] ) );
 	}
 
-	$query = trim(
-		"
-		SELECT DISTINCT {$wpdb->prefix}evf_entries.entry_id
-		FROM {$wpdb->prefix}evf_entries
-		INNER JOIN {$wpdb->prefix}evf_entrymeta
-		WHERE {$wpdb->prefix}evf_entries.entry_id = {$wpdb->prefix}evf_entrymeta.entry_id
-		{$status}
-		{$search}
-		{$include}
-		{$exclude}
-		{$date_created}
-		{$date_modified}
-		{$order}
-		{$limit}
-		{$offset}
-		"
-	);
+	if ( ! empty( $args['status'] ) ) {
+		$query[] = $wpdb->prepare( 'AND `status` = %s', isset( $statuses[ $args['status'] ] ) ? $statuses[ $args['status'] ] : 'publish' );
+	}
 
-	$results = $wpdb->get_results( $query ); // WPCS: cache ok, DB call ok, unprepared SQL ok.
+	$orderby     = in_array( $args['orderby'], $valid_fields, true ) ? $args['orderby'] : 'entry_id';
+	$order       = 'DESC' === strtoupper( $args['order'] ) ? 'DESC' : 'ASC';
+	$orderby_sql = sanitize_sql_orderby( "{$orderby} {$order}" );
+	$query[]     = "ORDER BY {$orderby_sql}";
+
+	if ( -1 < $args['limit'] ) {
+		$query[] = $wpdb->prepare( 'LIMIT %d', absint( $args['limit'] ) );
+	}
+
+	if ( 0 < $args['offset'] ) {
+		$query[] = $wpdb->prepare( 'LIMIT %d', absint( $args['offset'] ) );
+	}
+
+	// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
+	$results = $wpdb->get_results( implode( ' ', $query ), ARRAY_A );
 
 	$ids = wp_list_pluck( $results, 'entry_id' );
 
```
