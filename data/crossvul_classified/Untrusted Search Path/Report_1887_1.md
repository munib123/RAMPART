# CrossVul Fix Pair: Untrusted Search Path in go
**Pair ID:** 1887_1
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_1`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```go
Lines 1-30 of the vulnerable file.

package commands

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/git-lfs/git-lfs/config"
	"github.com/git-lfs/git-lfs/errors"
	"github.com/git-lfs/git-lfs/filepathfilter"
	"github.com/git-lfs/git-lfs/git"
	"github.com/git-lfs/git-lfs/lfs"
	"github.com/git-lfs/git-lfs/lfsapi"
	"github.com/git-lfs/git-lfs/locking"
	"github.com/git-lfs/git-lfs/subprocess"
	"github.com/git-lfs/git-lfs/tools"
	"github.com/git-lfs/git-lfs/tq"
)

// Populate man pages
//go:generate go run ../docs/man/mangen.go

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,6 @@
 	"log"
 	"net"
 	"os"
-	"os/exec"
 	"path/filepath"
 	"strings"
 	"sync"
@@ -282,7 +281,7 @@
 }
 
 func PipeCommand(name string, args ...string) error {
-	cmd := exec.Command(name, args...)
+	cmd := subprocess.ExecCommand(name, args...)
 	cmd.Stdin = os.Stdin
 	cmd.Stderr = os.Stderr
 	cmd.Stdout = os.Stdout
```
