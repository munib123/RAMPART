# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3551_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3551_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 135-175 of the vulnerable file.

	 * @param DataObject|string|int The item to save, as either a DataObject or the ID.
	 * @param array $extraFields Map of extra fields.
	 */
	protected function loadChildIntoDatabase($item, $extraFields = null) {
		if($this->type == '1-to-many') {
			$child = DataObject::get_by_id($this->childClass,$item->ID);
			if (!$child) $child = $item;
			$joinField = $this->joinField;
			$child->$joinField = $this->ownerObj->ID;
			$child->write();
			
		} else {		
			$parentField = $this->ownerClass . 'ID';
			$childField = ($this->childClass == $this->ownerClass) ? "ChildID" : ($this->childClass . 'ID');
			
			DB::query( "DELETE FROM \"$this->tableName\" WHERE \"$parentField\" = {$this->ownerObj->ID} AND \"$childField\" = {$item->ID}" );
			
			$extraKeys = $extraValues = '';
			if($extraFields) foreach($extraFields as $k => $v) {
				$extraKeys .= ", \"$k\"";
				$extraValues .= ", '" . DB::getConn()->addslashes($v) . "'";
			}

			DB::query("INSERT INTO \"$this->tableName\" (\"$parentField\",\"$childField\" $extraKeys) VALUES ({$this->ownerObj->ID}, {$item->ID} $extraValues)");
		}
	}
    	
	/**
	 * Add a number of items to the component set.
	 * @param array $items Items to add, as either DataObjects or IDs.
	 */
	function addMany($items) {
		foreach($items as $item) {
			$this->add($item);
		}
	}
	
	/**
	 * Sets the ComponentSet to be the given ID list.
	 * Records will be added and deleted as appropriate.
	 * @param array $idList List of IDs.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,7 +152,7 @@
 			$extraKeys = $extraValues = '';
 			if($extraFields) foreach($extraFields as $k => $v) {
 				$extraKeys .= ", \"$k\"";
-				$extraValues .= ", '" . DB::getConn()->addslashes($v) . "'";
+				$extraValues .= ", '" . Convert::raw2sql($v) . "'";
 			}
 
 			DB::query("INSERT INTO \"$this->tableName\" (\"$parentField\",\"$childField\" $extraKeys) VALUES ({$this->ownerObj->ID}, {$item->ID} $extraValues)");
```
