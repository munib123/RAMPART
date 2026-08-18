# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in cpp
**Pair ID:** 4235_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4235_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```cpp
Lines 84-124 of the vulnerable file.


  return !isEOF();
}


bool TarFileReader::next() {
  if (didReadHeader) {
    skipFile(pri->filter);
    didReadHeader = false;
  }

  return hasMore();
}


std::string TarFileReader::extract(const string &_path) {
  if (_path.empty()) THROW("path cannot be empty");
  if (!hasMore()) THROW("No more tar files");

  string path = _path;
  if (SystemUtilities::isDirectory(path)) path += "/" + getFilename();

  LOG_DEBUG(5, "Extracting: " << path);

  return extract(*SystemUtilities::oopen(path));
}


string TarFileReader::extract(ostream &out) {
  if (!hasMore()) THROW("No more tar files");

  readFile(out, pri->filter);
  didReadHeader = false;

  return getFilename();
}


void TarFileReader::addCompression(compression_t compression) {
  switch (compression) {
  case TARFILE_NONE: break; // none
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,11 +101,26 @@
   if (!hasMore()) THROW("No more tar files");
 
   string path = _path;
-  if (SystemUtilities::isDirectory(path)) path += "/" + getFilename();
+  if (SystemUtilities::isDirectory(path)) {
+    path += "/" + getFilename();
+
+    // Check that path is under the target directory
+    string a = SystemUtilities::getCanonicalPath(_path);
+    string b = SystemUtilities::getCanonicalPath(path);
+    if (!String::startsWith(b, a))
+      THROW("Tar path points outside of the extraction directory: " << path);
+  }
 
   LOG_DEBUG(5, "Extracting: " << path);
 
-  return extract(*SystemUtilities::oopen(path));
+  switch (getType()) {
+  case NORMAL_FILE: case CONTIGUOUS_FILE:
+    return extract(*SystemUtilities::oopen(path));
+  case DIRECTORY: SystemUtilities::ensureDirectory(path); break;
+  default: THROW("Unsupported tar file type " << getType());
+  }
+
+  return getFilename();
 }
 
 
```
