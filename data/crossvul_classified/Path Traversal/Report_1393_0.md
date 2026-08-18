# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1393_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1393_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 113-154 of the vulnerable file.

    var stream = fs.createReadStream(archive);

    var reject = function(error) {
        destroy(stream);
        deferred.reject(error);
    };
    stream
        .on('error', reject)
        .pipe(zlib.createGunzip())
        .on('error', reject)
        .pipe(createWriteStream(dst))
        .on('error', reject)
        .on('finish', function(result) {
            destroy(stream);
            deferred.resolve(dst);
        });

    return deferred.promise;
}

function isSymlink(entry) {
    return entry.type === 'SymbolicLink';
}

function filterSymlinks(entry) {
    return entry.type !== 'SymbolicLink';
}

function getExtractor(archive) {
    // Make the archive lower case to match against the types
    // This ensures that upper-cased extensions work
    archive = archive.toLowerCase();

    var type = mout.array.find(extractorTypes, function(type) {
        return mout.string.endsWith(archive, type);
    });

    return type ? extractors[type] : null;
}

function isSingleDir(dir) {
    return Q.nfcall(fs.readdir, dir).then(function(files) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,8 +130,8 @@
     return deferred.promise;
 }
 
-function isSymlink(entry) {
-    return entry.type === 'SymbolicLink';
+function isSymlink(_, entry) {
+    return entry.type === 'symlink';
 }
 
 function filterSymlinks(entry) {
```
