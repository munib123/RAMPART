# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 70_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `70_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 337-377 of the vulnerable file.

         * @return Boolean
         */
        extractEntryTo : function(/*Object*/entry, /*String*/targetPath, /*Boolean*/maintainEntryPath, /*Boolean*/overwrite) {
            overwrite = overwrite || false;
            maintainEntryPath = typeof maintainEntryPath == "undefined" ? true : maintainEntryPath;

            var item = getEntry(entry);
            if (!item) {
                throw Utils.Errors.NO_ENTRY;
            }

            var entryName = item.entryName;

            if(isWin){
                entryName = escapeFileName(entryName)
            }



            var target = pth.resolve(targetPath, maintainEntryPath ? entryName : pth.basename(entryName));

            if (item.isDirectory) {
                target = pth.resolve(target, "..");
                var children = _zip.getEntryChildren(item);
                children.forEach(function(child) {
                    if (child.isDirectory) return;
                    var content = child.getData();
                    if (!content) {
                        throw Utils.Errors.CANT_EXTRACT_FILE;
                    }

                    childName = child.entryName;

                    if(isWin){
                        childName = escapeFileName(childName)
                    }

                    Utils.writeFileTo(pth.resolve(targetPath, maintainEntryPath ? childName : childName.substr(entryName.length)), content, overwrite);
                });
                return true;
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -354,6 +354,9 @@
 
 
             var target = pth.resolve(targetPath, maintainEntryPath ? entryName : pth.basename(entryName));
+            if(!target.startsWith(targetPath)) {
+                throw Utils.Errors.INVALID_FILENAME + ": " + entryName;
+            }
 
             if (item.isDirectory) {
                 target = pth.resolve(target, "..");
@@ -429,6 +432,10 @@
             _zip.entries.forEach(function(entry) {
                 entryName = entry.entryName.toString();
 
+                if(!pth.resolve(targetPath, entryName).startsWith(targetPath)) {
+                    throw Utils.Errors.INVALID_FILENAME + ": " + entryName;
+                }
+
                 if(isWin){
                     entryName = escapeFileName(entryName)
                 }
@@ -469,6 +476,10 @@
 
                 if(isWin){
                     entryName = escapeFileName(entryName)
+                }
+
+                if(!pth.resolve(targetPath, entryName).startsWith(targetPath)) {
+                  throw Utils.Errors.INVALID_FILENAME + ": " + entryName;
                 }
 
                 if (entry.isDirectory) {
```
