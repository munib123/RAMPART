# CrossVul Fix Pair: Untrusted Search Path in go
**Pair ID:** 1887_2
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_2`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```go
Lines 1-35 of the vulnerable file.

package config

import (
	"fmt"
	"runtime"
	"strings"
)

var (
	GitCommit   string
	VersionDesc string
	Vendor      string
)

const (
	Version = "2.13.1"
)

func init() {
	gitCommit := ""
	if len(GitCommit) > 0 {
		gitCommit = "; git " + GitCommit
	}
	if len(Vendor) == 0 {
		Vendor = "GitHub"
	}
	VersionDesc = fmt.Sprintf("git-lfs/%s (%s; %s %s; go %s%s)",
		Version,
		Vendor,
		runtime.GOOS,
		runtime.GOARCH,
		strings.Replace(runtime.Version(), "go", "", 1),
		gitCommit,
	)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 )
 
 const (
-	Version = "2.13.1"
+	Version = "2.13.2"
 )
 
 func init() {
```
