# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 37_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `37_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 305-345 of the vulnerable file.

            $logs = $this->getPrettyFormat($command);
        } catch (\RuntimeException $e) {
            return [];
        }

        foreach ($logs as $log) {
            $commit = new Commit();
            $commit->importData($log);
            $commits[] = $commit;
        }

        return $commits;
    }

    public function searchTree($query, $branch)
    {
        if (empty($query)) {
            return null;
        }

        $query = escapeshellarg($query);

        try {
            $results = $this->getClient()->run($this, "grep -i --line-number {$query} $branch");
        } catch (\RuntimeException $e) {
            return false;
        }

        $results = explode("\n", $results);

        foreach ($results as $result) {
            if ($result == '') {
                continue;
            }

            preg_match_all('/([\w-._]+):([^:]+):([0-9]+):(.+)/', $result, $matches, PREG_SET_ORDER);

            $data['branch'] = $matches[0][1];
            $data['file'] = $matches[0][2];
            $data['line'] = $matches[0][3];
            $data['match'] = $matches[0][4];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -322,15 +322,17 @@
             return null;
         }
 
+        $query = preg_replace('/(--?[A-Za-z0-9\-]+)/', '', $query);
         $query = escapeshellarg($query);
 
         try {
-            $results = $this->getClient()->run($this, "grep -i --line-number {$query} $branch");
+            $results = $this->getClient()->run($this, "grep -i --line-number -- {$query} $branch");
         } catch (\RuntimeException $e) {
             return false;
         }
 
         $results = explode("\n", $results);
+        $searchResults = [];
 
         foreach ($results as $result) {
             if ($result == '') {
```
