# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5032_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5032_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 497-537 of the vulnerable file.

    public function write($template = '')
    {
        if (!empty($this->script_files)) {
            $this->set_env('request_token', $this->app->get_request_token());
        }

        $commands = $this->get_js_commands($framed);

        // if all js commands go to parent window we can ignore all
        // script files and skip rcube_webmail initialization (#1489792)
        if ($framed) {
            $this->scripts      = array();
            $this->script_files = array();
            $this->header       = '';
            $this->footer       = '';
        }

        // write all javascript commands
        $this->add_script($commands, 'head_top');

        // send clickjacking protection headers
        $iframe = $this->framed || $this->env['framed'];
        if (!headers_sent() && ($xframe = $this->app->config->get('x_frame_options', 'sameorigin'))) {
            header('X-Frame-Options: ' . ($iframe && $xframe == 'deny' ? 'sameorigin' : $xframe));
        }

        // call super method
        $this->_write($template, $this->config->get('skin_path'));
    }

    /**
     * Parse a specific skin template and deliver to stdout (or return)
     *
     * @param  string  Template name
     * @param  boolean Exit script
     * @param  boolean Don't write to stdout, return parsed content instead
     *
     * @link   http://php.net/manual/en/function.exit.php
     */
    function parse($name = 'main', $exit = true, $write = true)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -514,10 +514,10 @@
         // write all javascript commands
         $this->add_script($commands, 'head_top');
 
-        // send clickjacking protection headers
+        // allow (legal) iframe content to be loaded
         $iframe = $this->framed || $this->env['framed'];
-        if (!headers_sent() && ($xframe = $this->app->config->get('x_frame_options', 'sameorigin'))) {
-            header('X-Frame-Options: ' . ($iframe && $xframe == 'deny' ? 'sameorigin' : $xframe));
+        if (!headers_sent() && $iframe && $this->app->config->get('x_frame_options', 'sameorigin') === 'deny') {
+            header('X-Frame-Options: sameorigin', true);
         }
 
         // call super method
```
