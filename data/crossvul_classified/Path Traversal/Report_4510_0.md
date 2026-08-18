# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 4510_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4510_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 4-44 of the vulnerable file.

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package installer // import "helm.sh/helm/v3/pkg/plugin/installer"

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"helm.sh/helm/v3/internal/third_party/dep/fs"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/helmpath"
	"helm.sh/helm/v3/pkg/plugin/cache"
)

// HTTPInstaller installs plugins from an archive served by a web server.
type HTTPInstaller struct {
	CacheDir   string
	PluginName string
	base
	extractor Extractor
	getter    getter.Getter
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,10 +21,12 @@
 	"compress/gzip"
 	"io"
 	"os"
+	"path"
 	"path/filepath"
 	"regexp"
 	"strings"
 
+	securejoin "github.com/cyphar/filepath-securejoin"
 	"github.com/pkg/errors"
 
 	"helm.sh/helm/v3/internal/third_party/dep/fs"
@@ -118,7 +120,7 @@
 	}
 
 	if err := i.extractor.Extract(pluginData, i.CacheDir); err != nil {
-		return err
+		return errors.Wrap(err, "extracting files from archive")
 	}
 
 	if !isPlugin(i.CacheDir) {
@@ -146,6 +148,58 @@
 		return ""
 	}
 	return helmpath.DataPath("plugins", i.PluginName)
+}
+
+// CleanJoin resolves dest as a subpath of root.
+//
+// This function runs several security checks on the path, generating an error if
+// the supplied `dest` looks suspicious or would result in dubious behavior on the
+// filesystem.
+//
+// CleanJoin assumes that any attempt by `dest` to break out of the CWD is an attempt
+// to be malicious. (If you don't care about this, use the securejoin-filepath library.)
+// It will emit an error if it detects paths that _look_ malicious, operating on the
+// assumption that we don't actually want to do anything with files that already
+// appear to be nefarious.
+//
+//   - The character `:` is considered illegal because it is a separator on UNIX and a
+//     drive designator on Windows.
+//   - The path component `..` is considered suspicions, and therefore illegal
+//   - The character \ (backslash) is treated as a path separator and is converted to /.
+//   - Beginning a path with a path separator is illegal
+//   - Rudimentary symlink protects are offered by SecureJoin.
+func cleanJoin(root, dest string) (string, error) {
+
+	// On Windows, this is a drive separator. On UNIX-like, this is the path list separator.
+	// In neither case do we want to trust a TAR that contains these.
+	if strings.Contains(dest, ":") {
+		return "", errors.New("path contains ':', which is illegal")
+	}
+
+	// The Go tar library does not convert separators for us.
+	// We assume here, as we do elsewhere, that `\\` means a Windows path.
+	dest = strings.ReplaceAll(dest, "\\", "/")
+
+	// We want to alert the user that something bad was attempted. Cleaning it
+	// is not a good practice.
+	for _, part := range strings.Split(dest, "/") {
+		if part == ".." {
+			return "", errors.New("path contains '..', which is illegal")
+		}
+	}
+
+	// If a path is absolute, the creator of the TAR is doing something shady.
+	if path.IsAbs(dest) {
+		return "", errors.New("path is absolute, which is illegal")
+	}
+
+	// SecureJoin will do some cleaning, as well as some rudimentary checking of symlinks.
+	newpath, err := securejoin.SecureJoin(root, dest)
+	if err != nil {
+		return "", err
+	}
+
+	return filepath.ToSlash(newpath), nil
 }
 
 // Extract extracts compressed archives
@@ -171,7 +225,10 @@
 			return err
 		}
 
-		path := filepath.Join(targetDir, header.Name)
+		path, err := cleanJoin(targetDir, header.Name)
+		if err != nil {
+			return err
+		}
 
 		switch header.Typeflag {
 		case tar.TypeDir:
```
