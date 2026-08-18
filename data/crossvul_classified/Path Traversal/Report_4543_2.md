# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4543_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4543_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 18-48 of the vulnerable file.


        foreach ($files as $file) {
            try {
                $chunked ?
                    $this->handleChunkedUpload($file, $response, $request) :
                    $this->handleUpload($file, $response, $request)
                ;
            } catch (UploadException $e) {
                $this->errorHandler->addException($response, $e);
            }
        }

        return $this->createSupportedJsonResponse($response->assemble());
    }

    protected function parseChunkedRequest(Request $request)
    {
        $session = $this->container->get('session');

        $orig = $request->get('name');
        $index = $request->get('chunk');
        $last = (int) $request->get('chunks') - 1 === (int) $request->get('chunk');

        // it is possible, that two clients send a file with the
        // exact same filename, therefore we have to add the session
        // to the uuid otherwise we will get a mess
        $uuid = md5(sprintf('%s.%s', $orig, $session->getId()));

        return [$last, $uuid, $index, $orig];
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
         $session = $this->container->get('session');
 
         $orig = $request->get('name');
-        $index = $request->get('chunk');
+        $index = (int) $request->get('chunk');
         $last = (int) $request->get('chunks') - 1 === (int) $request->get('chunk');
 
         // it is possible, that two clients send a file with the
```
