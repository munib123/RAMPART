# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4543_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4543_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 81-121 of the vulnerable file.

                $this->filesystem->delete($key);
            } catch (\Exception $e) {
                continue;
            }
        }
    }

    /**
     * Only saves the information about the chunk to avoid moving it
     * forth-and-back to reassemble it. Load distribution is enforced
     * for gaufrette based chunk storage therefore assembleChunks will
     * be called in the same request.
     *
     * @param              $uuid
     * @param              $index
     * @param UploadedFile $chunk
     * @param              $original
     */
    public function addChunk($uuid, $index, UploadedFile $chunk, $original)
    {
        $this->unhandledChunk = [
            'uuid' => $uuid,
            'index' => $index,
            'chunk' => $chunk,
            'original' => $original,
        ];
    }

    public function assembleChunks($chunks, $removeChunk, $renameChunk)
    {
        // the index is only added to be in sync with the filesystem storage
        $path = $this->prefix.'/'.$this->unhandledChunk['uuid'].'/';
        $filename = $this->unhandledChunk['index'].'_'.$this->unhandledChunk['original'];

        if (empty($chunks)) {
            $target = $filename;
            $this->ensureRemotePathExists($path.$target);
        } else {
            /*
             * The array only contains items with matching prefix until the filename
             * therefore the order will be decided depending on the filename
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,6 +98,9 @@
      */
     public function addChunk($uuid, $index, UploadedFile $chunk, $original)
     {
+        // Prevent path traversal attacks
+        $uuid = basename($uuid);
+
         $this->unhandledChunk = [
             'uuid' => $uuid,
             'index' => $index,
@@ -170,6 +173,9 @@
 
     public function getChunks($uuid)
     {
+        // Prevent path traversal attacks
+        $uuid = basename($uuid);
+
         $results = $this->filesystem->listKeys($this->prefix.'/'.$uuid);
 
         /* exclude files without an index, so if there is a completed file which
```
