# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5390_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5390_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 101-141 of the vulnerable file.

	 * expPaginator Constructor
	 *
	 * This is the main entry point for using the expPaginator.  See example above.
	 *
	 * @param array $params Use this to set any of the class variables. Ones not passed will be set to a default.
	 * @return \expPaginator
	 */
	public function __construct($params=array()) {
		global $router, $db;

        $this->pages_to_show = expTheme::is_mobile() ? 6 : 10; // fewer paging links for small devices
		$this->where = empty($params['where']) ? null : $params['where'];
		$this->records = empty($params['records']) ? array() : $params['records'];
//		$this->limit = empty($params['limit']) ? 10 : $params['limit'];
        $this->limit = empty($params['limit']) ? 0 : intval($params['limit']);
        $this->page = empty($params['page']) ? 1 : intval($params['page']);
		$this->action = empty($params['action']) ? '' : $params['action'];
		$this->controller = empty($params['controller']) ? '' : $params['controller'];
		$this->sql = empty($params['sql']) ? '' : $params['sql'];
        $this->count_sql = empty($params['count_sql']) ? '' : $params['count_sql'];
		$this->order = empty($params['order']) ? 'id' : expString::escape($params['order']);
		$this->dir = empty($params['dir']) || !in_array($params['dir'], array('ASC', 'DESC')) ? 'ASC' : $params['dir'];
		$this->src = empty($params['src']) ? null : expString::escape($params['src']);
        $this->categorize = empty($params['categorize']) ? false : $params['categorize'];
        $this->uncat = !empty($params['uncat']) ? $params['uncat'] : gt('Not Categorized');
        $this->groups = !empty($params['groups']) ? $params['groups'] : array();
        $this->grouplimit = !empty($params['grouplimit']) ? $params['grouplimit'] : null;
        $this->dontsortwithincat = !empty($params['dontsortwithincat']) ? $params['dontsortwithincat'] : null;
        $this->dontsort = !empty($params['dontsort']) ? $params['dontsort'] : null;

		// if a view was passed we'll use it.
		if (isset($params['view']))
            $this->view = $params['view'];

        // setup the model if one was passed.
        if (isset($params['model'])) {
            $this->model = $params['model'];
            $class = new $this->model(null, false, false);
        }

	    // auto-include the CSS for pagination links
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,7 +118,7 @@
 		$this->controller = empty($params['controller']) ? '' : $params['controller'];
 		$this->sql = empty($params['sql']) ? '' : $params['sql'];
         $this->count_sql = empty($params['count_sql']) ? '' : $params['count_sql'];
-		$this->order = empty($params['order']) ? 'id' : expString::escape($params['order']);
+        $this->order = empty($params['order']) ? 'id' : preg_replace('/[^a-z\_]/i','',$params['order']);
 		$this->dir = empty($params['dir']) || !in_array($params['dir'], array('ASC', 'DESC')) ? 'ASC' : $params['dir'];
 		$this->src = empty($params['src']) ? null : expString::escape($params['src']);
         $this->categorize = empty($params['categorize']) ? false : $params['categorize'];
```
