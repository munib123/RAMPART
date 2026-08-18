# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4073_7
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_7`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 197-238 of the vulnerable file.

                if ($entry->ip == $ip) {
                    $found = true;
                    break;
                }

        if (!$found)
            return errorJsonResponse("This domain/ip association does not exist");

        pihole_execute("-a removecustomdns ".$ip." ".$domain);

        return successJsonResponse();
    }
    catch (\Exception $ex)
    {
        return errorJsonResponse($ex->getMessage());
    }
}

function deleteAllCustomDNSEntries()
{
    $handle = fopen($customDNSFile, "r");
    if ($handle)
    {
        try
        {
            while (($line = fgets($handle)) !== false) {
                $line = str_replace("\r","", $line);
                $line = str_replace("\n","", $line);
                $explodedLine = explode (" ", $line);

                if (count($explodedLine) != 2)
                    continue;

                $ip = $explodedLine[0];
                $domain = $explodedLine[1];

                pihole_execute("-a removecustomdns ".$ip." ".$domain);
            }
        }
        catch (\Exception $ex)
        {
            return errorJsonResponse($ex->getMessage());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,31 +214,34 @@
 
 function deleteAllCustomDNSEntries()
 {
-    $handle = fopen($customDNSFile, "r");
-    if ($handle)
-    {
-        try
+    if (isset($customDNSFile))
+    {
+        $handle = fopen($customDNSFile, "r");
+        if ($handle)
         {
-            while (($line = fgets($handle)) !== false) {
-                $line = str_replace("\r","", $line);
-                $line = str_replace("\n","", $line);
-                $explodedLine = explode (" ", $line);
-
-                if (count($explodedLine) != 2)
-                    continue;
-
-                $ip = $explodedLine[0];
-                $domain = $explodedLine[1];
-
-                pihole_execute("-a removecustomdns ".$ip." ".$domain);
+            try
+            {
+                while (($line = fgets($handle)) !== false) {
+                    $line = str_replace("\r","", $line);
+                    $line = str_replace("\n","", $line);
+                    $explodedLine = explode (" ", $line);
+
+                    if (count($explodedLine) != 2)
+                        continue;
+
+                    $ip = $explodedLine[0];
+                    $domain = $explodedLine[1];
+
+                    pihole_execute("-a removecustomdns ".$ip." ".$domain);
+                }
             }
-        }
-        catch (\Exception $ex)
-        {
-            return errorJsonResponse($ex->getMessage());
-        }
-
-        fclose($handle);
+            catch (\Exception $ex)
+            {
+                return errorJsonResponse($ex->getMessage());
+            }
+
+            fclose($handle);
+        }
     }
 
     return successJsonResponse();
```
