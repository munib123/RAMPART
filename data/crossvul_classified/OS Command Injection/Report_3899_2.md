# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3899_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3899_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 87-127 of the vulnerable file.

    $arguments = 'check';
} else if ($scope == 'clear') {
    if (!array_key_exists('id', $_GET)) {
        die("Missing 'id' argument on request.");
    } else if (!preg_match($id_regex, $id)) {
        $id = '';
    }
    $arguments = 'clear ' . escapeshellcmd($id);
} else if ($scope == 'run') {
    $json_wanted = false;

    $arguments = "run " . escapeshellarg(filter_input(INPUT_GET, "bot")) . " ";
    switch (filter_input(INPUT_GET, "cmd")) {
        case "get":
            $arguments .= "message get";
            break;
        case "pop":
            $arguments .= "message pop";
            break;
        case "send":
            $arguments .= "message send '" . escapeshellarg(filter_input(INPUT_POST, "msg")) . "'";
            break;
        case "process":
            $arguments .= "process";
            if(filter_input(INPUT_GET, "show", FILTER_VALIDATE_BOOLEAN)) {
                $arguments .= " --show-sent";
            }
            if(filter_input(INPUT_GET, "dry", FILTER_VALIDATE_BOOLEAN)) {
                $arguments .= " --dry";
            }
            if(filter_input(INPUT_POST, "msg")) {
                $arguments .= " --msg " . escapeshellarg(filter_input(INPUT_POST, "msg")) . "";
            }
            break;
        default:
            break;
    }
} else {
    die('Invalid scope');
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
             $arguments .= "message pop";
             break;
         case "send":
-            $arguments .= "message send '" . escapeshellarg(filter_input(INPUT_POST, "msg")) . "'";
+            $arguments .= "message send " . escapeshellarg(filter_input(INPUT_POST, "msg"));
             break;
         case "process":
             $arguments .= "process";
```
