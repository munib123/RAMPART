# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_9
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_9`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1037-1077 of the vulnerable file.

        if ($compression) {
            $key .= '_' . $compression;
        }

        return $key;
    }

    /**
     * Returns debug info
     *
     * @param boolean $cache
     * @param string $reason
     * @param boolean $status
     * @param double $time
     * @return string
     */
    function _get_debug_info($cache, $reason, $status, $time) {
        $engine = $this->_config->get_string('pgcache.engine');
        $debug_info = "<!-- W3 Total Cache: Page cache debug info:\r\n";
        $debug_info .= sprintf("%s%s\r\n", str_pad('Engine: ', 20), w3_get_engine_name($engine));
        $debug_info .= sprintf("%s%s\r\n", str_pad('Cache key: ', 20), $this->_page_key);
        $debug_info .= sprintf("%s%s\r\n", str_pad('Caching: ', 20), ($cache ? 'enabled' : 'disabled'));

        if (!$cache) {
            $debug_info .= sprintf("%s%s\r\n", str_pad('Reject reason: ', 20), $reason);
        }

        if ($engine != 'file_generic')
            $debug_info .= sprintf("%s%s\r\n", str_pad('Status: ', 20), ($status ? 'cached' : 'not cached'));
        $debug_info .= sprintf("%s%.3fs\r\n", str_pad('Creation Time: ', 20), $time);

        $headers = $this->_get_response_headers();

        if (count($headers)) {
            $debug_info .= "Header info:\r\n";

            foreach ($headers as $header_name => $header_value) {
                $debug_info .= sprintf("%s%s\r\n", str_pad($header_name . ': ', 20), w3_escape_comment($header_value));
            }
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1054,7 +1054,7 @@
         $engine = $this->_config->get_string('pgcache.engine');
         $debug_info = "<!-- W3 Total Cache: Page cache debug info:\r\n";
         $debug_info .= sprintf("%s%s\r\n", str_pad('Engine: ', 20), w3_get_engine_name($engine));
-        $debug_info .= sprintf("%s%s\r\n", str_pad('Cache key: ', 20), $this->_page_key);
+        $debug_info .= sprintf("%s%s\r\n", str_pad('Cache key: ', 20), w3_escape_comment($this->_page_key));
         $debug_info .= sprintf("%s%s\r\n", str_pad('Caching: ', 20), ($cache ? 'enabled' : 'disabled'));
 
         if (!$cache) {
@@ -1071,7 +1071,7 @@
             $debug_info .= "Header info:\r\n";
 
             foreach ($headers as $header_name => $header_value) {
-                $debug_info .= sprintf("%s%s\r\n", str_pad($header_name . ': ', 20), w3_escape_comment($header_value));
+                $debug_info .= sprintf("%s%s\r\n", str_pad(w3_escape_comment($header_name) . ': ', 20), w3_escape_comment($header_value));
             }
         }
 
```
