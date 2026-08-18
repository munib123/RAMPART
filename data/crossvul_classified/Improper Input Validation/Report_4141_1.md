# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4141_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4141_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 2-42 of the vulnerable file.

Copyright The Helm Authors.
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

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"helm.sh/helm/v3/cmd/helm/require"
	"helm.sh/helm/v3/pkg/plugin"
	"helm.sh/helm/v3/pkg/plugin/installer"
)

type pluginInstallOptions struct {
	source  string
	version string
}

const pluginInstallDesc = `
This command allows you to install a plugin from a url to a VCS repo or a local path.
`

func newPluginInstallCmd(out io.Writer) *cobra.Command {
	o := &pluginInstallOptions{}
	cmd := &cobra.Command{
		Use:     "install [options] <path|url>...",
		Short:   "install one or more Helm plugins",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 	"fmt"
 	"io"
 
+	"github.com/pkg/errors"
 	"github.com/spf13/cobra"
 
 	"helm.sh/helm/v3/cmd/helm/require"
@@ -81,7 +82,7 @@
 	debug("loading plugin from %s", i.Path())
 	p, err := plugin.LoadDir(i.Path())
 	if err != nil {
-		return err
+		return errors.Wrap(err, "plugin is installed but unusable")
 	}
 
 	if err := runHook(p, plugin.Install); err != nil {
```
