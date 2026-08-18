# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1641_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1641_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 408-448 of the vulnerable file.

			$data['address_2'] = '';
		}

		if (isset($this->request->post['postcode'])) {
			$data['postcode'] = $this->request->post['postcode'];
		} elseif (!empty($address_info)) {
			$data['postcode'] = $address_info['postcode'];
		} else {
			$data['postcode'] = '';
		}

		if (isset($this->request->post['city'])) {
			$data['city'] = $this->request->post['city'];
		} elseif (!empty($address_info)) {
			$data['city'] = $address_info['city'];
		} else {
			$data['city'] = '';
		}

		if (isset($this->request->post['country_id'])) {
			$data['country_id'] = $this->request->post['country_id'];
		}  elseif (!empty($address_info)) {
			$data['country_id'] = $address_info['country_id'];
		} else {
			$data['country_id'] = $this->config->get('config_country_id');
		}

		if (isset($this->request->post['zone_id'])) {
			$data['zone_id'] = $this->request->post['zone_id'];
		}  elseif (!empty($address_info)) {
			$data['zone_id'] = $address_info['zone_id'];
		} else {
			$data['zone_id'] = '';
		}

		$this->load->model('localisation/country');

		$data['countries'] = $this->model_localisation_country->getCountries();

		// Custom fields
		$this->load->model('account/custom_field');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -425,7 +425,7 @@
 		}
 
 		if (isset($this->request->post['country_id'])) {
-			$data['country_id'] = $this->request->post['country_id'];
+			$data['country_id'] = (int)$this->request->post['country_id'];
 		}  elseif (!empty($address_info)) {
 			$data['country_id'] = $address_info['country_id'];
 		} else {
@@ -433,7 +433,7 @@
 		}
 
 		if (isset($this->request->post['zone_id'])) {
-			$data['zone_id'] = $this->request->post['zone_id'];
+			$data['zone_id'] = (int)$this->request->post['zone_id'];
 		}  elseif (!empty($address_info)) {
 			$data['zone_id'] = $address_info['zone_id'];
 		} else {
@@ -503,11 +503,11 @@
 			$this->error['postcode'] = $this->language->get('error_postcode');
 		}
 
-		if ($this->request->post['country_id'] == '') {
+		if ($this->request->post['country_id'] == '' || !is_int($this->request->post['country_id'])) {
 			$this->error['country'] = $this->language->get('error_country');
 		}
 
-		if (!isset($this->request->post['zone_id']) || $this->request->post['zone_id'] == '') {
+		if (!isset($this->request->post['zone_id']) || $this->request->post['zone_id'] == '' || !is_int($this->request->post['zone_id'])) {
 			$this->error['zone'] = $this->language->get('error_zone');
 		}
 
```
