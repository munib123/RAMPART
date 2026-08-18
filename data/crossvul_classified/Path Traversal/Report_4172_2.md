# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 4172_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4172_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 1-21 of the vulnerable file.

// Copyright (c) 2019, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package unpacker

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sylabs/singularity/pkg/sylog"
)

// Squashfs represents a squashfs unpacker.
type Squashfs struct {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+// Copyright (c) 2020, Control Command Inc. All rights reserved.
 // Copyright (c) 2019, Sylabs Inc. All rights reserved.
 // This software is licensed under a 3-clause BSD license. Please consult the
 // LICENSE.md file distributed with the sources of this project regarding your
@@ -16,6 +17,33 @@
 
 	"github.com/sylabs/singularity/pkg/sylog"
 )
+
+const (
+	stdinFile = "/proc/self/fd/0"
+)
+
+var cmdFunc func(unsquashfs string, dest string, filename string, rootless bool) (*exec.Cmd, error)
+
+// unsquashfsCmd is the command instance for executing unsquashfs command
+// in a non sandboxed environment when this package is used for unit tests.
+func unsquashfsCmd(unsquashfs string, dest string, filename string, rootless bool) (*exec.Cmd, error) {
+	args := make([]string, 0)
+	if rootless {
+		args = append(args, "-user-xattrs")
+	}
+	// remove the destination directory if any, if the directory is
+	// not empty (typically during image build), the unsafe option -f is
+	// set, this is unfortunately required by image build
+	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
+		if !os.IsExist(err) {
+			return nil, fmt.Errorf("failed to remove %s: %s", dest, err)
+		}
+		// unsafe mode
+		args = append(args, "-f")
+	}
+	args = append(args, "-d", dest, filename)
+	return exec.Command(unsquashfs, args...), nil
+}
 
 // Squashfs represents a squashfs unpacker.
 type Squashfs struct {
@@ -41,7 +69,7 @@
 
 	// pipe over stdin by default
 	stdin := true
-	filename := "/proc/self/fd/0"
+	filename := stdinFile
 
 	if _, ok := reader.(*os.File); !ok {
 		// use the destination parent directory to store the
@@ -71,9 +99,12 @@
 	//  have to fall back to not using that option on failure.
 	if os.Geteuid() != 0 {
 		sylog.Debugf("Rootless extraction. Trying -user-xattrs for unsquashfs")
-		args := []string{"-user-xattrs", "-f", "-d", dest, filename}
-		args = append(args, files...)
-		cmd := exec.Command(s.UnsquashfsPath, args...)
+
+		cmd, err := cmdFunc(s.UnsquashfsPath, dest, filename, true)
+		if err != nil {
+			return fmt.Errorf("command error: %s", err)
+		}
+		cmd.Args = append(cmd.Args, files...)
 		if stdin {
 			cmd.Stdin = reader
 		}
@@ -85,7 +116,7 @@
 
 		// Invalid options give output...
 		// SYNTAX: unsquashfs [options] filesystem [directories or files to extract]
-		if bytes.HasPrefix(o, []byte("SYNTAX")) {
+		if bytes.Contains(o, []byte("SYNTAX")) {
 			sylog.Warningf("unsquashfs does not support -user-xattrs. Images with system xattrs may fail to extract")
 		} else {
 			// A different error is fatal
@@ -93,9 +124,11 @@
 		}
 	}
 
-	args := []string{"-f", "-d", dest, filename}
-	args = append(args, files...)
-	cmd := exec.Command(s.UnsquashfsPath, args...)
+	cmd, err := cmdFunc(s.UnsquashfsPath, dest, filename, false)
+	if err != nil {
+		return fmt.Errorf("command error: %s", err)
+	}
+	cmd.Args = append(cmd.Args, files...)
 	if stdin {
 		cmd.Stdin = reader
 	}
```
