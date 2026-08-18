# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 44-84 of the vulnerable file.

        setcookie('w3tc_preview', true, 0, '/');
        w3_redirect(w3_get_home_url());
    }

    /**
     * Stop previewing the site
     */
    function action_default_stop_previewing() {
        setcookie("w3tc_preview", "", time()-3600, '/');
        w3_admin_redirect(array(), true);
    }

    /**
     * Hide note action
     *
     * @return void
     */
    function action_default_save_licence_key() {
        $license = W3_Request::get_string('license_key');
        try {
            $this->_config->set('plugin.license_key', $license);
            $this->_config->save();
        } catch(Exception $ex){
            echo json_encode(array('result' => 'failed'));
            exit;
        }
        echo json_encode(array('result' => 'success'));
        exit;
    }

    /**
     * Hide note action
     *
     * @return void
     */
    function action_default_hide_note() {
        $note = W3_Request::get_string('note');
        $admin = W3_Request::get_boolean('admin');
        $setting = sprintf('notes.%s', $note);
        if ($admin) {
            $this->_config_admin->set($setting, false);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,8 +61,13 @@
     function action_default_save_licence_key() {
         $license = W3_Request::get_string('license_key');
         try {
+            $old_config = new W3_Config();
+
             $this->_config->set('plugin.license_key', $license);
             $this->_config->save();
+
+            w3_instance('W3_Licensing')->possible_state_change($this->_config,
++                $old_config);
         } catch(Exception $ex){
             echo json_encode(array('result' => 'failed'));
             exit;
```
