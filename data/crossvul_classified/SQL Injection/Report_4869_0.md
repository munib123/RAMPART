# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4869_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4869_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 476-516 of the vulnerable file.


		switch ($key) {
			case 'openbay_amazon_order_status_shipped':
				$order_status = 'shipped';
				break;
			case 'openbay_amazon_order_status_canceled':
				$order_status = 'canceled';
				break;

			default:
				$order_status = null;
				break;
		}

		return $order_status;
	}

	public function updateAmazonOrderTracking($order_id, $courier_id, $courier_from_list, $tracking_no) {
		$this->db->query("
			UPDATE `" . DB_PREFIX . "amazon_order`
			SET `courier_id` = '" . $courier_id . "',
				`courier_other` = " . (int)!$courier_from_list . ",
				`tracking_no` = '" . $tracking_no . "'
			WHERE `order_id` = " . (int)$order_id . "");
	}

	public function getAmazonOrderId($order_id) {
		$row = $this->db->query("
			SELECT `amazon_order_id`
			FROM `" . DB_PREFIX . "amazon_order`
			WHERE `order_id` = " . (int)$order_id . "
			LIMIT 1")->row;

		if (isset($row['amazon_order_id']) && !empty($row['amazon_order_id'])) {
			return $row['amazon_order_id'];
		}

		return null;
	}

	public function getAmazonOrderedProducts($order_id) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -493,9 +493,9 @@
 	public function updateAmazonOrderTracking($order_id, $courier_id, $courier_from_list, $tracking_no) {
 		$this->db->query("
 			UPDATE `" . DB_PREFIX . "amazon_order`
-			SET `courier_id` = '" . $courier_id . "',
+			SET `courier_id` = '" . $this->db->escape($courier_id) . "',
 				`courier_other` = " . (int)!$courier_from_list . ",
-				`tracking_no` = '" . $tracking_no . "'
+				`tracking_no` = '" . $this->db->escape($tracking_no) . "'
 			WHERE `order_id` = " . (int)$order_id . "");
 	}
 
```
