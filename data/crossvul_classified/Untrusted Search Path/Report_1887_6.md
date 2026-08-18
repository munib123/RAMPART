# CrossVul Fix Pair: Untrusted Search Path in go
**Pair ID:** 1887_6
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_6`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```go
Lines 1-27 of the vulnerable file.

package lfshttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/git-lfs/git-lfs/config"
	"github.com/git-lfs/git-lfs/subprocess"
	"github.com/git-lfs/git-lfs/tools"
	"github.com/rubyist/tracerx"
)

type SSHResolver interface {
	Resolve(Endpoint, string) (sshAuthResponse, error)
}

func withSSHCache(ssh SSHResolver) SSHResolver {
	return &sshCache{
		endpoints: make(map[string]*sshAuthResponse),
		ssh:       ssh,
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,6 @@
 	"bytes"
 	"encoding/json"
 	"fmt"
-	"os/exec"
 	"path/filepath"
 	"regexp"
 	"strings"
@@ -83,7 +82,7 @@
 	}
 
 	exe, args := sshGetLFSExeAndArgs(c.os, c.git, e, method)
-	cmd := exec.Command(exe, args...)
+	cmd := subprocess.ExecCommand(exe, args...)
 
 	// Save stdout and stderr in separate buffers
 	var outbuf, errbuf bytes.Buffer
```
