# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4543_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4543_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 23-51 of the vulnerable file.

                $chunked ?
                    $this->handleChunkedUpload($file, $response, $request) :
                    $this->handleUpload($file, $response, $request)
                ;
            } catch (UploadException $e) {
                $response->setSuccess(false);
                $response->setError($translator->trans($e->getMessage(), [], 'OneupUploaderBundle'));

                $this->errorHandler->addException($response, $e);

                // an error happended, return this error message.
                return $this->createSupportedJsonResponse($response->assemble());
            }
        }

        return $this->createSupportedJsonResponse($response->assemble());
    }

    protected function parseChunkedRequest(Request $request)
    {
        $index = $request->get('qqpartindex');
        $total = $request->get('qqtotalparts');
        $uuid = $request->get('qquuid');
        $orig = $request->get('qqfilename');
        $last = ((int) $total - 1) === (int) $index;

        return [$last, $uuid, $index, $orig];
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,11 +40,11 @@
 
     protected function parseChunkedRequest(Request $request)
     {
-        $index = $request->get('qqpartindex');
-        $total = $request->get('qqtotalparts');
+        $index = (int) $request->get('qqpartindex');
+        $total = (int) $request->get('qqtotalparts');
         $uuid = $request->get('qquuid');
         $orig = $request->get('qqfilename');
-        $last = ((int) $total - 1) === (int) $index;
+        $last = ($total - 1) === $index;
 
         return [$last, $uuid, $index, $orig];
     }
```
