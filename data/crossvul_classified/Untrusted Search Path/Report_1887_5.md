# CrossVul Fix Pair: Untrusted Search Path in go
**Pair ID:** 1887_5
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_5`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```go
Lines 1-31 of the vulnerable file.

package lfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/git-lfs/git-lfs/config"
)

type pipeRequest struct {
	action     string
	reader     io.Reader
	fileName   string
	extensions []config.Extension
}

type pipeResponse struct {
	file    *os.File
	results []*pipeExtResult
}

type pipeExtResult struct {
	name   string
	oidIn  string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,10 +8,10 @@
 	"hash"
 	"io"
 	"os"
-	"os/exec"
 	"strings"
 
 	"github.com/git-lfs/git-lfs/config"
+	"github.com/git-lfs/git-lfs/subprocess"
 )
 
 type pipeRequest struct {
@@ -33,7 +33,7 @@
 }
 
 type extCommand struct {
-	cmd    *exec.Cmd
+	cmd    *subprocess.Cmd
 	out    io.WriteCloser
 	err    *bytes.Buffer
 	hasher hash.Hash
@@ -75,7 +75,7 @@
 			arg := strings.Replace(value, "%f", request.fileName, -1)
 			args = append(args, arg)
 		}
-		cmd := exec.Command(name, args...)
+		cmd := subprocess.ExecCommand(name, args...)
 		ec := &extCommand{cmd: cmd, result: &pipeExtResult{name: e.Name}}
 		extcmds = append(extcmds, ec)
 	}
```
