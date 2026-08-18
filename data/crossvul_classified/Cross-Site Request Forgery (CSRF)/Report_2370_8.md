# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 318-358 of the vulnerable file.

     * @param string $file
     * @param mixed $data
     */
    function set_file_custom_data($file, $data) {
        if (preg_match('~' . MINIFY_AUTO_FILENAME_REGEX .'$~', $file, $matches)) {
            list(, $hash, $type) = $matches;

            $key = $this->get_custom_data_key($hash, $type);
            $this->_cache_set($key, $data);
        }
    }

    /**
     * Log
     *
     * @param string $msg
     * @return bool
     */
    function log($msg) {
        $data = sprintf("[%s] [%s] [%s] %s\n", date('r'), $_SERVER['REQUEST_URI'], (!empty($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '-'), $msg);

        $filename = w3_debug_log('minify');
        return @file_put_contents($filename, $data, FILE_APPEND);
    }

    /**
     * Returns minify groups
     *
     * @param string $theme
     * @param string $template
     * @param string $type
     * @return array
     */
    function get_groups($theme, $template, $type) {
        $result = array();

        switch ($type) {
            case 'css':
                $groups = $this->_config->get_array('minify.css.groups');
                break;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -335,6 +335,7 @@
      */
     function log($msg) {
         $data = sprintf("[%s] [%s] [%s] %s\n", date('r'), $_SERVER['REQUEST_URI'], (!empty($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '-'), $msg);
+        $data = strtr($data, '<>', '..');
 
         $filename = w3_debug_log('minify');
         return @file_put_contents($filename, $data, FILE_APPEND);
```
