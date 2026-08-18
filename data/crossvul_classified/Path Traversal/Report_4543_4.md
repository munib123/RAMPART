# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4543_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4543_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 48-88 of the vulnerable file.

            $timestamp = isset($key['timestamp']) ? $key['timestamp'] : $this->filesystem->getTimestamp($path);

            if ($maxAge <= $now - $timestamp) {
                $toDelete[] = $path;
            }
        }

        foreach ($toDelete as $path) {
            // The filesystem will throw exceptions if
            // a directory is not empty
            try {
                $this->filesystem->delete($path);
            } catch (\Exception $e) {
                continue;
            }
        }
    }

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
        } else {
            sort($chunks, SORT_STRING | SORT_FLAG_CASE);
            $target = pathinfo($chunks[0]['path'], PATHINFO_BASENAME);
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,9 @@
 
     public function addChunk($uuid, $index, UploadedFile $chunk, $original)
     {
+        // Prevent path traversal attacks
+        $uuid = basename($uuid);
+
         $this->unhandledChunk = [
             'uuid' => $uuid,
             'index' => $index,
@@ -136,6 +139,9 @@
 
     public function getChunks($uuid)
     {
+        // Prevent path traversal attacks
+        $uuid = basename($uuid);
+
         return $this->filesystem->listFiles($this->prefix.'/'.$uuid);
     }
 
```
