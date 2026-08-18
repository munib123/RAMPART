# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 111-148 of the vulnerable file.

        curl_close($ch);
    } catch (Exception $e) {
        return false;
    }

    return $result;
}

function checkService($ip = "localhost", $port = '6661')
{
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false) {
        throw new Exception("Socket Creation Failed");
    }

    // Connect to the node server.
    $result = socket_connect($socket, $ip, $port);
    if ($result === false) {
        $path = $GLOBALS['fileroot'] . "/ccdaservice";
        if (IS_WINDOWS) {
            $cmd = "node " . $path . "/serveccda.js";
            pclose(popen("start /B " . $cmd, "r"));
        } else {
            $cmd = "nodejs " . $path . "/serveccda.js";
            exec($cmd . " > /dev/null &");
        }
        sleep(2); // give cpu a rest
        $result = socket_connect($socket, $ip, $port);
        if ($result === false) { // hmm something is amist with service.
            throw new Exception("Connection Failed");
        }
    }
    socket_close($socket);
    unset($socket);
    return true;
}

return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,10 +128,10 @@
     if ($result === false) {
         $path = $GLOBALS['fileroot'] . "/ccdaservice";
         if (IS_WINDOWS) {
-            $cmd = "node " . $path . "/serveccda.js";
+            $cmd = "node " . escapeshellarg($path . "/serveccda.js");
             pclose(popen("start /B " . $cmd, "r"));
         } else {
-            $cmd = "nodejs " . $path . "/serveccda.js";
+            $cmd = "nodejs " . escapeshellarg($path . "/serveccda.js");
             exec($cmd . " > /dev/null &");
         }
         sleep(2); // give cpu a rest
```
