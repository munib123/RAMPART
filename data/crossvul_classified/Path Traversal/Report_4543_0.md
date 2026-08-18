# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4543_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4543_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 25-57 of the vulnerable file.

                    $this->handleUpload($file, $response, $request)
                ;
            } catch (UploadException $e) {
                $statusCode = 500; //Dropzone displays error if HTTP response is 40x or 50x
                $this->errorHandler->addException($response, $e);
                $translator = $this->container->get('translator');
                $message = $translator->trans($e->getMessage(), [], 'OneupUploaderBundle');
                $response = $this->createSupportedJsonResponse(['error' => $message]);
                $response->setStatusCode(400);

                return $response;
            }
        }

        return $this->createSupportedJsonResponse($response->assemble(), $statusCode);
    }

    protected function parseChunkedRequest(Request $request)
    {
        $totalChunkCount = $request->get('dztotalchunkcount');
        $index = $request->get('dzchunkindex');
        $last = ((int) $index + 1) === (int) $totalChunkCount;
        $uuid = $request->get('dzuuid');

        /**
         * @var UploadedFile
         */
        $file = $request->files->get('file')->getClientOriginalName();
        $orig = $file;

        return [$last, $uuid, $index, $orig];
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,8 +42,8 @@
     protected function parseChunkedRequest(Request $request)
     {
         $totalChunkCount = $request->get('dztotalchunkcount');
-        $index = $request->get('dzchunkindex');
-        $last = ((int) $index + 1) === (int) $totalChunkCount;
+        $index = (int) $request->get('dzchunkindex');
+        $last = ($index + 1) === (int) $totalChunkCount;
         $uuid = $request->get('dzuuid');
 
         /**
```
