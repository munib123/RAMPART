# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in php
**Pair ID:** 1438_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1438_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```php
Lines 149-189 of the vulnerable file.

    }

    function disable() {
        $this->enabled = false;
    }

    function enable() {
        $this->enabled = true;
    }

    function log($level, $leveltext, $msg) {
        // Run only if output will be used
        if ($level >= min($this->loglevel, $this->echolevel, $this->firelevel) && $this->enabled) {
            $logmessage = "";
            $backtrace = "";
            $showrequest = false; // Maybe show _REQUEST array
            // Process exceptions
            if ($msg instanceof Exception || $msg instanceof Error) {
                $excmessage = method_exists($msg, 'getDetailMessage') ? $msg->getDetailMessage() : $msg->getMessage();
                $logmessage = $leveltext.": ".$excmessage."\n".Log::prettybacktrace($msg->getTrace());
                $showrequest = true;
            } else {
                $logmessage = $leveltext.": ". print_r($msg,true)."\n";
                // Generate a backtrace if it was requested or in severe cases
                if ($level == Log::BACKTRACE || $level >= Log::FAIL) {
                    $backtrace = "\n".Log::prettybacktrace();
                    $showrequest = true;
                }
            }

            if (!headers_sent() && $level >= $this->firelevel) {
                $this->log_firephp($msg,$level);
            }
            
            // Append request variables to log message if so desired
            if ($showrequest && count($_REQUEST) > 0) $logmessage .= "REQUEST ".print_r($_REQUEST, true);

            // Write to logfile
            if ($this->file && $level >= $this->loglevel) {
                $logfile = fopen($this->file, 'a');
                if ($logfile) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -166,13 +166,11 @@
             if ($msg instanceof Exception || $msg instanceof Error) {
                 $excmessage = method_exists($msg, 'getDetailMessage') ? $msg->getDetailMessage() : $msg->getMessage();
                 $logmessage = $leveltext.": ".$excmessage."\n".Log::prettybacktrace($msg->getTrace());
-                $showrequest = true;
             } else {
                 $logmessage = $leveltext.": ". print_r($msg,true)."\n";
                 // Generate a backtrace if it was requested or in severe cases
                 if ($level == Log::BACKTRACE || $level >= Log::FAIL) {
                     $backtrace = "\n".Log::prettybacktrace();
-                    $showrequest = true;
                 }
             }
 
```
