# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1946_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1946_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

(function (tree) {

    var parseCopyProperties = [
        'paths',            // option - unmodified - paths to search for imports on
        'optimization',     // option - optimization level (for the chunker)
        'files',            // list of files that have been imported, used for import-once
        'contents',         // map - filename to contents of all the files
        'contentsIgnoredChars', // map - filename to lines at the begining of each file to ignore
        'relativeUrls',     // option - whether to adjust URL's to be relative
        'rootpath',         // option - rootpath to append to URL's
        'strictImports',    // option -
        'insecure',         // option - whether to allow imports from insecure ssl hosts
        'dumpLineNumbers',  // option - whether to dump line numbers
        'compress',         // option - whether to compress
        'processImports',   // option - whether to process imports. if false then imports will not be imported
        'syncImport',       // option - whether to import synchronously
        'javascriptEnabled',// option - whether JavaScript is enabled. if undefined, defaults to true
        'mime',             // browser only - mime type for sheet import
        'useFileCache',     // browser only - whether to use the per file session cache
        'currentFileInfo'   // information about the current file - for error reporting and importing and making urls relative etc.
    ];

    //currentFileInfo = {
    //  'relativeUrls' - option - whether to adjust URL's to be relative
    //  'filename' - full resolved filename of current file
    //  'rootpath' - path to append to normal URLs for this node
    //  'currentDirectory' - path to the current file, absolute
    //  'rootFilename' - filename of the base file
    //  'entryPath' - absolute path to the entry file
    //  'reference' - whether the file should not be output and only output parts that are referenced

    tree.parseEnv = function(options) {
        copyFromOriginal(options, this, parseCopyProperties);

        if (!this.contents) { this.contents = {}; }
        if (!this.contentsIgnoredChars) { this.contentsIgnoredChars = {}; }
        if (!this.files) { this.files = {}; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,9 @@
         'compress',         // option - whether to compress
         'processImports',   // option - whether to process imports. if false then imports will not be imported
         'syncImport',       // option - whether to import synchronously
-        'javascriptEnabled',// option - whether JavaScript is enabled. if undefined, defaults to true
+        /* BEGIN MODIFICATION */
+        // Removed 'javascriptEnabled'
+        /* END MODIFICATION */
         'mime',             // browser only - mime type for sheet import
         'useFileCache',     // browser only - whether to use the per file session cache
         'currentFileInfo'   // information about the current file - for error reporting and importing and making urls relative etc.
```
