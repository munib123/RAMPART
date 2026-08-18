# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4543_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4543_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

    {
        $system = new Filesystem();
        $finder = new Finder();

        try {
            $finder->in($this->directory)->date('<='.-1 * (int) $maxAge.'seconds')->files();
        } catch (\InvalidArgumentException $e) {
            // the finder will throw an exception of type InvalidArgumentException
            // if the directory he should search in does not exist
            // in that case we don't have anything to clean
            return;
        }

        foreach ($finder as $file) {
            $system->remove($file);
        }
    }

    public function addChunk($uuid, $index, UploadedFile $chunk, $original)
    {
        $filesystem = new Filesystem();
        $path = sprintf('%s/%s', $this->directory, $uuid);
        $name = sprintf('%s_%s', $index, $original);

        // create directory if it does not yet exist
        if (!$filesystem->exists($path)) {
            $filesystem->mkdir(sprintf('%s/%s', $this->directory, $uuid));
        }

        return $chunk->move($path, $name);
    }

    public function assembleChunks($chunks, $removeChunk, $renameChunk)
    {
        if (!($chunks instanceof \IteratorAggregate)) {
            throw new \InvalidArgumentException('The first argument must implement \IteratorAggregate interface.');
        }

        $iterator = $chunks->getIterator();

        $base = $iterator->current();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,9 @@
 
     public function addChunk($uuid, $index, UploadedFile $chunk, $original)
     {
+        // Prevent path traversal attacks
+        $uuid = basename($uuid);
+
         $filesystem = new Filesystem();
         $path = sprintf('%s/%s', $this->directory, $uuid);
         $name = sprintf('%s_%s', $index, $original);
@@ -106,6 +109,9 @@
 
     public function getChunks($uuid)
     {
+        // Prevent path traversal attacks
+        $uuid = basename($uuid);
+
         $finder = new Finder();
         $finder
             ->in(sprintf('%s/%s', $this->directory, $uuid))->files()->sort(function (\SplFileInfo $a, \SplFileInfo $b) {
```
