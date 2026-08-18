# CrossVul Fix Pair: Untrusted Search Path in go
**Pair ID:** 1887_3
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_3`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```go
Lines 1-34 of the vulnerable file.

package creds

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/git-lfs/git-lfs/config"
	"github.com/git-lfs/git-lfs/errors"
	"github.com/rubyist/tracerx"
)

// CredentialHelperWrapper is used to contain the encapsulate the information we need for credential handling during auth.
type CredentialHelperWrapper struct {
	CredentialHelper CredentialHelper
	Input            Creds
	Url              *url.URL
	Creds            Creds
}

// CredentialHelper is an interface used by the lfsapi Client to interact with
// the 'git credential' command: https://git-scm.com/docs/gitcredentials
// Other implementations include ASKPASS support, and an in-memory cache.
type CredentialHelper interface {
	Fill(Creds) (Creds, error)
	Reject(Creds) error
	Approve(Creds) error
}

func (credWrapper *CredentialHelperWrapper) FillCreds() error {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 
 	"github.com/git-lfs/git-lfs/config"
 	"github.com/git-lfs/git-lfs/errors"
+	"github.com/git-lfs/git-lfs/subprocess"
 	"github.com/rubyist/tracerx"
 )
 
@@ -232,7 +233,7 @@
 
 	// 'cmd' will run the GIT_ASKPASS (or core.askpass) command prompting
 	// for the desired valueType (`Username` or `Password`)
-	cmd := exec.Command(a.Program, a.args(fmt.Sprintf("%s for %q", valueString, u))...)
+	cmd := subprocess.ExecCommand(a.Program, a.args(fmt.Sprintf("%s for %q", valueString, u))...)
 	cmd.Stderr = &err
 	cmd.Stdout = &value
 
@@ -292,7 +293,7 @@
 
 func (h *commandCredentialHelper) exec(subcommand string, input Creds) (Creds, error) {
 	output := new(bytes.Buffer)
-	cmd := exec.Command("git", "credential", subcommand)
+	cmd := subprocess.ExecCommand("git", "credential", subcommand)
 	cmd.Stdin = bufferCreds(input)
 	cmd.Stdout = output
 	/*
```
