# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in cpp
**Pair ID:** 2420_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2420_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```cpp
Lines 1-40 of the vulnerable file.

/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-2016 Facebook, Inc. (http://www.facebook.com)     |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/
#include <zip.h>

#include "hphp/runtime/base/array-init.h"
#include "hphp/runtime/base/preg.h"
#include "hphp/runtime/base/stream-wrapper-registry.h"
#include "hphp/runtime/ext/extension.h"
#include "hphp/runtime/ext/pcre/ext_pcre.h"
#include "hphp/runtime/ext/std/ext_std_file.h"

namespace HPHP {

static String to_full_path(const String& filename) {
  if (filename.charAt(0) == '/') {
    return filename;
  }
  return f_getcwd().toString() + String::FromChar('/') + filename;
}

// A wrapper for `zip_open` that prepares a full path
// file name to consider current working directory.
static zip* _zip_open(const String& filename, int _flags, int* zep) {
  return zip_open(to_full_path(filename).c_str(), _flags, zep);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 #include <zip.h>
 
 #include "hphp/runtime/base/array-init.h"
+#include "hphp/runtime/base/file-util.h"
 #include "hphp/runtime/base/preg.h"
 #include "hphp/runtime/base/stream-wrapper-registry.h"
 #include "hphp/runtime/ext/extension.h"
@@ -650,25 +651,103 @@
   return true;
 }
 
+// Make the path relative to "." by flattening.
+// This function is named the same and similar in implementation to that in
+// php-src:php_zip.c
+// One difference is that we canonicalize here whereas php-src is already
+// assumed passed a canonicalized path.
+static std::string make_relative_path(const std::string& path) {
+  if (path.empty()) {
+    return path;
+  }
+
+  // First get the path to a state where we don't have .. in the middle of it
+  // etc. canonicalize handles Windows paths too.
+  std::string canonical(FileUtil::canonicalize(path));
+
+  // If we have a slash at the beginning, then just remove it and we are
+  // relative. This check will hold because we have canonicalized the
+  // path above to remove .. from the path, so we know we can be sure
+  // we are at a good place for this check.
+  if (FileUtil::isDirSeparator(canonical[0])) {
+    return canonical.substr(1);
+  }
+
+  // If we get here, canonical looks something like:
+  //   a/b/c
+
+  // Search through the path and if we find a place where we have a slash
+  // and a "." just before that slash, then cut the path off right there
+  // and just take everything after the slash.
+  std::string relative(canonical);
+  int idx = canonical.length() - 1;
+  while (1) {
+    while (idx > 0 && !(FileUtil::isDirSeparator(canonical[idx]))) {
+      idx--;
+    }
+    // If we ever get to idx == 0, then there were no other slashes to deal with
+    if (idx == 0) {
+      return canonical;
+    }
+    if (idx >= 1 && (canonical[idx - 1] == '.' || canonical[idx - 1] == ':')) {
+      relative = canonical.substr(idx + 1);
+      break;
+    }
+    idx--;
+  }
+  return relative;
+}
+
 static bool extractFileTo(zip* zip, const std::string &file, std::string& to,
                           char* buf, size_t len) {
-  auto sep = file.rfind('/');
+
+  struct zip_stat zipStat;
+  // Verify the file to be extracted is actually in the zip file
+  if (zip_stat(zip, file.c_str(), 0, &zipStat) != 0) {
+    return false;
+  }
+
+  auto clean_file = file;
+  auto sep = std::string::npos;
+  // Normally would just use std::string::rfind here, but if we want to be
+  // consistent between Windows and Linux, even if techincally Linux won't use
+  // backslash for a separator, we are checking for both types.
+  int idx = file.length() - 1;
+  while (idx >= 0) {
+    if (FileUtil::isDirSeparator(file[idx])) {
+      sep = idx;
+      break;
+    }
+    idx--;
+  }
   if (sep != std::string::npos) {
-    auto path = to + file.substr(0, sep);
+    // make_relative_path so we do not try to put files or dirs in bad
+    // places. This securely "cleans" the file.
+    clean_file = make_relative_path(file);
+    std::string path = to + clean_file;
+    bool is_dir_only = true;
+    if (sep < file.length() - 1) { // not just a directory
+      auto clean_file_dir = HHVM_FN(dirname)(clean_file);
+      path = to + clean_file_dir.toCppString();
+      is_dir_only = false;
+    }
+
+    // Make sure the directory path to extract to exists or can be created
     if (!HHVM_FN(is_dir)(path) && !HHVM_FN(mkdir)(path, 0777, true)) {
       return false;
     }
 
-    if (sep == file.length() - 1) {
+    // If we have a good directory to extract to above, we now check whether
+    // the "file" parameter passed in is a directory or actually a file.
+    if (is_dir_only) { // directory, like /usr/bin/
       return true;
     }
-  }
-
-  to.append(file);
-  struct zip_stat zipStat;
-  if (zip_stat(zip, file.c_str(), 0, &zipStat) != 0) {
-    return false;
-  }
+    // otherwise file is actually a file, so we actually extract.
+  }
+
+  // We have ensured that clean_file will be added to a relative path by the
+  // time we get here.
+  to.append(clean_file);
 
   auto zipFile = zip_fopen_index(zip, zipStat.index, 0);
   FAIL_IF_INVALID_PTR(zipFile);
```
