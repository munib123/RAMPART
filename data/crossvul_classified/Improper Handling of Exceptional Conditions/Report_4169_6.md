# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_6
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_6`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 1-9 of the vulnerable file.

// +build tools

package fosite

import (
	_ "github.com/gorilla/websocket"
	_ "github.com/mattn/goveralls"
	_ "github.com/ory/go-acc"
)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,5 +5,6 @@
 import (
 	_ "github.com/gorilla/websocket"
 	_ "github.com/mattn/goveralls"
+
 	_ "github.com/ory/go-acc"
 )
```
