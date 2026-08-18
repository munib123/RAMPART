# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 27-71 of the vulnerable file.

     */
    public function action_edge_mode_enable() {
        w3_require_once(W3TC_INC_FUNCTIONS_DIR . '/activation.php');
        $config_path = w3_get_wp_config_path();

        $config_data = @file_get_contents($config_path);
        if ($config_data === false)
            return;

        $new_config_data = $this->wp_config_evaluation_mode_remove_from_content($config_data);
        $new_config_data = preg_replace(
            '~<\?(php)?~',
            "\\0\r\n" . $this->wp_config_evaluation_mode(),
            $new_config_data,
            1);

        if ($new_config_data != $config_data) {
            try {
                w3_wp_write_to_file($config_path, $new_config_data);
            } catch (FilesystemOperationException $ex) {
                throw new FilesystemModifyException(
                    $ex->getMessage(), $ex->credentials_form(),
                    'Edit file <strong>' . $config_path .
                    '</strong> and add the next lines:', $config_path,
                    $this->wp_config_evaluation_mode());
            }
            try {
                $this->_config_admin->set('notes.edge_mode', false);
                $this->_config_admin->save();
            } catch (Exception $ex) {}
        }
        w3_admin_redirect(array('w3tc_note' => 'enabled_edge'));
    }


    /**
     * @return string Addon required for plugin in wp-config
     **/
    private function wp_config_evaluation_mode() {
        return "/** Enable W3 Total Cache Edge Mode */\r\n" .
        "define('W3TC_EDGE_MODE', true); // Added by W3 Total Cache\r\n";
    }

    /**
     * Disables WP_CACHE
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,11 +44,8 @@
             try {
                 w3_wp_write_to_file($config_path, $new_config_data);
             } catch (FilesystemOperationException $ex) {
-                throw new FilesystemModifyException(
-                    $ex->getMessage(), $ex->credentials_form(),
-                    'Edit file <strong>' . $config_path .
-                    '</strong> and add the next lines:', $config_path,
-                    $this->wp_config_evaluation_mode());
+                throw new Exception('Configuration file not writable. Please edit file <strong>' . $config_path .
+                    '</strong> and add the next lines: '. $this->wp_config_evaluation_mode());
             }
             try {
                 $this->_config_admin->set('notes.edge_mode', false);
```
