# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4500_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4500_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 411-451 of the vulnerable file.

                $status = Response::HTTP_NOT_FOUND;
            } else {
                $status = Response::HTTP_INTERNAL_SERVER_ERROR;
            }

            return $this->json($msg, $status);
        }
    }

    /**
     * Check that file extensions are not being changed.
     *
     * @param string $oldName
     * @param string $newName
     *
     * @return bool
     */
    private function isExtensionChangedAndIsChangeAllowed($oldName, $newName)
    {
        $user = $this->getUser();
        if ($this->users()->hasRole($user['id'], 'root') || $this->users()->hasRole($user['id'], 'admin')) {
            return true;
        }

        $oldFile = new \SplFileInfo($oldName);
        $newFile = new \SplFileInfo($newName);

        return $oldFile->getExtension() === $newFile->getExtension();
    }

    /**
     * Log an exception to the system log.
     *
     * @param string     $message   A formatted error message
     * @param \Exception $exception The exception that has been thrown
     *
     * @return bool Whether the record has been processed
     */
    private function logException($message, $exception)
    {
        return $this->app['logger.system']->error(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -428,6 +428,7 @@
     private function isExtensionChangedAndIsChangeAllowed($oldName, $newName)
     {
         $user = $this->getUser();
+
         if ($this->users()->hasRole($user['id'], 'root') || $this->users()->hasRole($user['id'], 'admin')) {
             return true;
         }
@@ -465,11 +466,12 @@
         if ($filename[0] === '.') {
             return false;
         }
+
         // only whitelisted extensions
         $extension = pathinfo($filename, PATHINFO_EXTENSION);
         $allowedExtensions = $this->getAllowedUploadExtensions();
 
-        return $extension === '' || in_array(mb_strtolower($extension), $allowedExtensions);
+        return in_array(mb_strtolower($extension), $allowedExtensions);
     }
 
     /**
```
