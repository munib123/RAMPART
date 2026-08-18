# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 961_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `961_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 139-179 of the vulnerable file.

	 *
	 * @since  1.0
	 * @access public
	 *
	 * @return void
	 */
	public function init() {
	}


	/**
	 * Set query filter.
	 *
	 * @since  1.8.9
	 * @access private
	 */
	private function set_filters() {
		// Reset param to apply filters.
		// While set filters $args will get override and multiple get_payments call will not work.
		$this->args = $this->_args;

		$this->date_filter_pre();
		$this->orderby();
		$this->status();
		$this->month();
		$this->per_page();
		$this->page();
		$this->user();
		$this->donor();
		$this->search();
		$this->mode();
		$this->children();
		$this->give_forms();
		$this->gateway_filter();

		add_filter( 'posts_orderby', array( $this, 'custom_orderby' ), 10, 2 );

		/**
		 * Fires after setup filters.
		 *
		 * @since 1.0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,6 +156,9 @@
 		// Reset param to apply filters.
 		// While set filters $args will get override and multiple get_payments call will not work.
 		$this->args = $this->_args;
+
+		// Whitelist order.
+		$this->args['order'] = in_array( strtoupper( $this->args['order'] ), array( 'ASC', 'DESC' ) ) ? $this->args['order'] : 'DESC' ;
 
 		$this->date_filter_pre();
 		$this->orderby();
```
