# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5326_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5326_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 102-132 of the vulnerable file.


	function update_vendor() {
		$vendor = new vendor();

		$vendor->update($this->params['vendor']);
        expHistory::back();
    }

	function delete_vendor() {
		global $db;

        if (!empty($this->params['id'])){
			$db->delete('vendor', 'id =' .$this->params['id']);
		}
        expHistory::back();
    }

	public function getPurchaseOrderByJSON() {

		if(!empty($this->params['vendor'])) {
			$purchase_orders = $this->purchase_order->find('all', 'vendor_id=' . $this->params['vendor']);
		} else {
			$purchase_orders = $this->purchase_order->find('all');
		}

		echo json_encode($purchase_orders);
	}

}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,7 +119,7 @@
 	public function getPurchaseOrderByJSON() {
 
 		if(!empty($this->params['vendor'])) {
-			$purchase_orders = $this->purchase_order->find('all', 'vendor_id=' . $this->params['vendor']);
+			$purchase_orders = $this->purchase_order->find('all', 'vendor_id=' . expString::escape($this->params['vendor']));
 		} else {
 			$purchase_orders = $this->purchase_order->find('all');
 		}
```
