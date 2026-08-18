# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4141_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4141_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 3-43 of the vulnerable file.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin // import "helm.sh/helm/v3/pkg/plugin"

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"sigs.k8s.io/yaml"

	"helm.sh/helm/v3/pkg/cli"
)

const PluginFileName = "plugin.yaml"

// Downloaders represents the plugins capability if it can retrieve
// charts from special sources
type Downloaders struct {
	// Protocols are the list of schemes from the charts URL.
	Protocols []string `json:"protocols"`
	// Command is the executable path with which the plugin performs
	// the actual download for the corresponding Protocols
	Command string `json:"command"`
}

// PlatformCommand represents a command for a particular operating system and architecture
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,9 +20,11 @@
 	"io/ioutil"
 	"os"
 	"path/filepath"
+	"regexp"
 	"runtime"
 	"strings"
 
+	"github.com/pkg/errors"
 	"sigs.k8s.io/yaml"
 
 	"helm.sh/helm/v3/pkg/cli"
@@ -157,18 +159,51 @@
 	return main, baseArgs, nil
 }
 
+// validPluginName is a regular expression that validates plugin names.
+//
+// Plugin names can only contain the ASCII characters a-z, A-Z, 0-9, ​_​ and ​-.
+var validPluginName = regexp.MustCompile("^[A-Za-z0-9_-]+$")
+
+// validatePluginData validates a plugin's YAML data.
+func validatePluginData(plug *Plugin, filepath string) error {
+	if !validPluginName.MatchString(plug.Metadata.Name) {
+		return fmt.Errorf("invalid plugin name at %q", filepath)
+	}
+	// We could also validate SemVer, executable, and other fields should we so choose.
+	return nil
+}
+
+func detectDuplicates(plugs []*Plugin) error {
+	names := map[string]string{}
+
+	for _, plug := range plugs {
+		if oldpath, ok := names[plug.Metadata.Name]; ok {
+			return fmt.Errorf(
+				"two plugins claim the name %q at %q and %q",
+				plug.Metadata.Name,
+				oldpath,
+				plug.Dir,
+			)
+		}
+		names[plug.Metadata.Name] = plug.Dir
+	}
+
+	return nil
+}
+
 // LoadDir loads a plugin from the given directory.
 func LoadDir(dirname string) (*Plugin, error) {
-	data, err := ioutil.ReadFile(filepath.Join(dirname, PluginFileName))
+	pluginfile := filepath.Join(dirname, PluginFileName)
+	data, err := ioutil.ReadFile(pluginfile)
 	if err != nil {
-		return nil, err
+		return nil, errors.Wrapf(err, "failed to read plugin at %q", pluginfile)
 	}
 
 	plug := &Plugin{Dir: dirname}
 	if err := yaml.Unmarshal(data, &plug.Metadata); err != nil {
-		return nil, err
-	}
-	return plug, nil
+		return nil, errors.Wrapf(err, "failed to load plugin at %q", pluginfile)
+	}
+	return plug, validatePluginData(plug, pluginfile)
 }
 
 // LoadAll loads all plugins found beneath the base directory.
@@ -180,7 +215,7 @@
 	scanpath := filepath.Join(basedir, "*", PluginFileName)
 	matches, err := filepath.Glob(scanpath)
 	if err != nil {
-		return plugins, err
+		return plugins, errors.Wrapf(err, "failed to find plugins in %q", scanpath)
 	}
 
 	if matches == nil {
@@ -195,7 +230,7 @@
 		}
 		plugins = append(plugins, p)
 	}
-	return plugins, nil
+	return plugins, detectDuplicates(plugins)
 }
 
 // FindPlugins returns a list of YAML files that describe plugins.
```
