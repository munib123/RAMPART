# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 960_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `960_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 798-838 of the vulnerable file.


		$this->__unset( 'gateway' );

	}


	/**
	 * Get sql query
	 *
	 * Note: Internal purpose only. We are developing on this fn.
	 *
	 * @since  1.8.18
	 * @access public
	 * @global $wpdb
	 *
	 * @return string
	 */
	private function get_sql() {
		global $wpdb;

		$where = "WHERE {$wpdb->posts}.post_type = 'give_payment'";
		$where .= " AND {$wpdb->posts}.post_status IN ('" . implode( "','", $this->args['post_status'] ) . "')";

		if ( is_numeric( $this->args['post_parent'] ) ) {
			$where .= " AND {$wpdb->posts}.post_parent={$this->args['post_parent']}";
		}

		// Set orderby.
		$orderby  = "ORDER BY {$wpdb->posts}.{$this->args['orderby']}";
		$group_by = '';

		// Set group by.
		if ( ! empty( $this->args['group_by'] ) ) {
			$group_by = "GROUP BY {$wpdb->posts}.{$this->args['group_by']}";
		}

		// Set offset.
		if (
			empty( $this->args['nopaging'] ) &&
			empty( $this->args['offset'] ) &&
			( ! empty( $this->args['page'] ) && 0 < $this->args['page'] )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -815,6 +815,26 @@
 	private function get_sql() {
 		global $wpdb;
 
+		$allowed_keys = array(
+			'post_name',
+			'post_author',
+			'post_date',
+			'post_title',
+			'post_status',
+			'post_modified',
+			'post_parent',
+			'post_type',
+			'menu_order',
+			'comment_count',
+		);
+
+		$this->args['orderby'] = 'post_parent__in';
+
+		// Whitelist orderby.
+		if( ! in_array( $this->args['orderby'], $allowed_keys ) ) {
+			$this->args['orderby'] = 'ID';
+		}
+
 		$where = "WHERE {$wpdb->posts}.post_type = 'give_payment'";
 		$where .= " AND {$wpdb->posts}.post_status IN ('" . implode( "','", $this->args['post_status'] ) . "')";
 
```
