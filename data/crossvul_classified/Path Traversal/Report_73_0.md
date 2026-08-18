# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 73_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `73_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 1-30 of the vulnerable file.

package archiver

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// Archiver represent a archive format
type Archiver interface {
	// Match checks supported files
	Match(filename string) bool
	// Make makes an archive file on disk.
	Make(destination string, sources []string) error
	// Open extracts an archive file on disk.
	Open(source, destination string) error
	// Write writes an archive to a Writer.
	Write(output io.Writer, sources []string) error
	// Read reads an archive from a Reader.
	Read(input io.Reader, destination string) error
}

// SupportedFormats contains all supported archive formats
var SupportedFormats = map[string]Archiver{}

// RegisterFormat adds a supported archive format
func RegisterFormat(name string, format Archiver) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 	"os"
 	"path/filepath"
 	"runtime"
+	"strings"
 )
 
 // Archiver represent a archive format
@@ -105,3 +106,14 @@
 	}
 	return nil
 }
+
+func sanitizeExtractPath(filePath string, destination string) error {
+	// to avoid zip slip (writing outside of the destination), we resolve
+	// the target path, and make sure it's nested in the intended
+	// destination, or bail otherwise.
+	destpath := filepath.Join(destination, filePath)
+	if !strings.HasPrefix(destpath, destination) {
+		return fmt.Errorf("%s: illegal file path", filePath)
+	}
+	return nil
+}
```
