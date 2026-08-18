# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 490_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `490_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 1-21 of the vulnerable file.

// Copyright 2018 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package tool

import (
	"strings"
)

// IsSameSiteURLPath returns true if the URL path belongs to the same site, false otherwise.
// False: //url, http://url, /\url
// True: /url
func IsSameSiteURLPath(url string) bool {
	return len(url) >= 2 && url[0] == '/' && url[1] != '/' && url[1] != '\\'
}

// SanitizePath sanitizes user-defined file paths to prevent remote code execution.
func SanitizePath(path string) string {
	return strings.TrimLeft(path, "./")
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,5 +17,7 @@
 
 // SanitizePath sanitizes user-defined file paths to prevent remote code execution.
 func SanitizePath(path string) string {
-	return strings.TrimLeft(path, "./")
+	path = strings.TrimLeft(path, "/")
+	path = strings.Replace(path, "../", "", -1)
+	return path
 }
```
