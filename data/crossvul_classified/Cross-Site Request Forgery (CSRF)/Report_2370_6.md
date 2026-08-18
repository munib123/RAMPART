# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 47-71 of the vulnerable file.


        return $this->_api;
    }
    
    /**
     * Write log entry
     *
     * @param string $message
     * @param array $backtrace
     * @return bool|int
     */
    protected function _log($message, $backtrace = null) {
        if (!$this->_debug)
            return true;

        $data = sprintf("[%s] %s\n", date('r'), $message);
        if ($backtrace) {
            $debug = print_r($backtrace, true);
            $data .= $debug . "\n";
        }
        $filename = w3_debug_log('sns');

        return @file_put_contents($filename, $data, FILE_APPEND);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,6 +64,8 @@
             $debug = print_r($backtrace, true);
             $data .= $debug . "\n";
         }
+        $data = strtr($data, '<>', '..');
+        
         $filename = w3_debug_log('sns');
 
         return @file_put_contents($filename, $data, FILE_APPEND);
```
