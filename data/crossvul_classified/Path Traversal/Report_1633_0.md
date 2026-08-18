# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 1633_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1633_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 192-232 of the vulnerable file.


    protected function addAsset()
    {
        $success = false;

        if (array_key_exists("Filedata", $_FILES)) {
            $filename = $_FILES["Filedata"]["name"];
            $sourcePath = $_FILES["Filedata"]["tmp_name"];
        } else if ($this->getParam("type") == "base64") {
            $filename = $this->getParam("filename");
            $sourcePath = PIMCORE_SYSTEM_TEMP_DIRECTORY . "/upload-base64" . uniqid() . ".tmp";
            $data = preg_replace("@^data:[^,]+;base64,@", "", $this->getParam("data"));
            File::put($sourcePath, base64_decode($data));
        }

        if($this->getParam("dir") && $this->getParam("parentId")) {
            // this is for uploading folders with Drag&Drop
            // param "dir" contains the relative path of the file
            $parent = Asset::getById($this->getParam("parentId"));
            $newPath = $parent->getFullPath() . "/" . trim($this->getParam("dir"), "/ ");

            $maxRetries = 5;
            for ($retries=0; $retries<$maxRetries; $retries++) {
                try {
                    $newParent = Asset\Service::createFolderByPath($newPath);
                    break;
                } catch (\Exception $e) {
                    if($retries < ($maxRetries-1)) {
                        $waitTime = rand(100000, 900000); // microseconds
                        usleep($waitTime); // wait specified time until we restart the transaction
                    } else {
                        // if the transaction still fail after $maxRetries retries, we throw out the exception
                        throw $e;
                    }
                }
            }

            $this->setParam("parentId", $newParent->getId());
        } else if (!$this->getParam("parentId") && $this->getParam("parentPath")) {
            $parent = Asset::getByPath($this->getParam("parentPath"));
            if ($parent instanceof Asset\Folder) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,6 +209,13 @@
             // param "dir" contains the relative path of the file
             $parent = Asset::getById($this->getParam("parentId"));
             $newPath = $parent->getFullPath() . "/" . trim($this->getParam("dir"), "/ ");
+
+            // check if the path is outside of the asset directory
+            $newRealPath = PIMCORE_ASSET_DIRECTORY . $newPath;
+            $newRealPath= realpath($newRealPath);
+            if (strpos($newRealPath, PIMCORE_ASSET_DIRECTORY) !== 0) {
+                throw new Exception("not allowed");
+            }
 
             $maxRetries = 5;
             for ($retries=0; $retries<$maxRetries; $retries++) {
```
