# CrossVul Fix Pair: NULL Pointer Dereference in go
**Pair ID:** 4330_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4330_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```go
Lines 1-16 of the vulnerable file.

// +build !windows

package errors

import "syscall"

// Abort will terminate & sends SIGTERM to process
func Abort(i ...int) {
	pgid, err := syscall.Getpgid(syscall.Getpid())
	if err != nil {
		Exit(err.Error())
	}

	// nolint:errcheck
	syscall.Kill(-pgid, syscall.SIGTERM)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,10 +2,17 @@
 
 package errors
 
-import "syscall"
+import (
+	"os"
+	"syscall"
+)
 
 // Abort will terminate & sends SIGTERM to process
 func Abort(i ...int) {
+	if _, err := os.Stat("/.dockerenv"); err == nil {
+		os.Exit(i[0])
+	}
+
 	pgid, err := syscall.Getpgid(syscall.Getpid())
 	if err != nil {
 		Exit(err.Error())
```
