# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 2184_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2184_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 248-288 of the vulnerable file.

						'reward'          => $reward * $quantity,
						'points'          => ($product_query->row['points'] ? ($product_query->row['points'] + $option_points) * $quantity : 0),
						'tax_class_id'    => $product_query->row['tax_class_id'],
						'weight'          => ($product_query->row['weight'] + $option_weight) * $quantity,
						'weight_class_id' => $product_query->row['weight_class_id'],
						'length'          => $product_query->row['length'],
						'width'           => $product_query->row['width'],
						'height'          => $product_query->row['height'],
						'length_class_id' => $product_query->row['length_class_id']
					);
				} else {
					$this->remove($key);
				}
			}
		}

		return $this->data;
	}

	public function add($product_id, $qty = 1, $option = array()) {
		if (!$option) {
			$key = (int)$product_id;
		} else {
			$key = (int)$product_id . ':' . base64_encode(serialize($option));
		}

		if ((int)$qty && ((int)$qty > 0)) {
			if (!isset($this->session->data['cart'][$key])) {
				$this->session->data['cart'][$key] = (int)$qty;
			} else {
				$this->session->data['cart'][$key] += (int)$qty;
			}
		}

		$this->data = array();
	}

	public function update($key, $qty) {
		if ((int)$qty && ((int)$qty > 0)) {
			$this->session->data['cart'][$key] = (int)$qty;
		} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -265,7 +265,7 @@
 	}
 
 	public function add($product_id, $qty = 1, $option = array()) {
-		if (!$option) {
+		if (!$option || !is_array($option)) {
 			$key = (int)$product_id;
 		} else {
 			$key = (int)$product_id . ':' . base64_encode(serialize($option));
@@ -283,7 +283,7 @@
 	}
 
 	public function update($key, $qty) {
-		if ((int)$qty && ((int)$qty > 0)) {
+		if ((int)$qty && ((int)$qty > 0) && isset($this->session->data['cart'][$key])) {
 			$this->session->data['cart'][$key] = (int)$qty;
 		} else {
 			$this->remove($key);
```
