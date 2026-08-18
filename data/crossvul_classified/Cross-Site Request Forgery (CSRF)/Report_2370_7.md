# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 124-164 of the vulnerable file.

        }

        if ($this->site_activated) {
            w3_e_error_box("<p>" . __('The W3 Total Cache license key is activated for this site.', 'w3-total-cache') ."</p>");
        }
    }

    /**
     * @return string
     */
    function update_license_status() {
        $status = '';
        $license_key = $this->get_license_key();

        if (!empty($license_key) || defined('W3TC_LICENSE_CHECK')) {
            $license = edd_w3edge_w3tc_check_license($license_key, W3TC_VERSION);
            $version = '';

            if ($license) {
                $status = $license->license;
                if ('host_valid' == $status) {
                    $version = 'pro';
                } elseif (in_array($status, array('site_inactive','valid')) && w3tc_is_pro_dev_mode()) {
                    $status = 'valid';
                    $version = 'pro_dev';
                }
            }

            $this->_config->set('plugin.type', $version);
        } else {
            $status = 'no_key';
            $this->_config->set('plugin.type', '');
        }
        try {
            $this->_config->save();
        } catch(Exception $ex) {}
        return $status;
    }

    /**
     * @return string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,7 +141,7 @@
 
             if ($license) {
                 $status = $license->license;
-                if ('host_valid' == $status) {
+                if (in_array($status, array('valid', 'host_valid'))) {
                     $version = 'pro';
                 } elseif (in_array($status, array('site_inactive','valid')) && w3tc_is_pro_dev_mode()) {
                     $status = 'valid';
```
