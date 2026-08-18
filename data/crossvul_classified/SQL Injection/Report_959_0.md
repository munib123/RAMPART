# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 959_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `959_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 449-489 of the vulnerable file.

	 *
	 * @return string
	 */
	private function get_order_query() {
		$table_columns = Give()->donors->get_columns();

		$query = array();
		$ordersby = $this->args['orderby'];

		if( ! is_array( $ordersby ) ) {
			$ordersby = array(
				$this->args['orderby'] => $this->args['order']
			);
		}

		// Remove non existing column.
		// Filter orderby values.
		foreach ( $ordersby as $orderby => $order ) {
			if( ! array_key_exists( $orderby, $table_columns ) ) {
				unset( $ordersby[$orderby] );
			}

			$ordersby[ esc_sql( $orderby ) ] = esc_sql( $order );
		}

		if( empty( $ordersby ) ) {
			$ordersby = array(
				'id' => $this->args['order']
			);
		}

		// Create query.
		foreach ( $ordersby as $orderby => $order ) {
			switch ( $table_columns[ $orderby ] ) {
				case '%d':
				case '%f':
					$query[] = "{$this->table_name}.{$orderby}+0 {$order}";
					break;

				default:
					$query[] = "{$this->table_name}.{$orderby} {$order}";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -466,6 +466,7 @@
 		foreach ( $ordersby as $orderby => $order ) {
 			if( ! array_key_exists( $orderby, $table_columns ) ) {
 				unset( $ordersby[$orderby] );
+				continue;
 			}
 
 			$ordersby[ esc_sql( $orderby ) ] = esc_sql( $order );
```
