# CrossVul Fix Pair: Incorrect Resource Transfer Between Spheres in go
**Pair ID:** 4193_1
**Vulnerability Class:** Incorrect Resource Transfer Between Spheres
**CWE:** CWE-669
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4193_1`)

## Vulnerability Information & PoC

## Description
Incorrect Resource Transfer Between Spheres - The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that r...

## Vulnerable Code
```go
Lines 7-47 of the vulnerable file.

   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package shim

import (
	gocontext "context"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"

	"github.com/containerd/console"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/runtime/v2/shim"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var fifoFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "stdin",
		Usage: "specify the path to the stdin fifo",
	},
	cli.StringFlag{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,7 @@
 	"io/ioutil"
 	"net"
 	"path/filepath"
+	"strings"
 
 	"github.com/containerd/console"
 	"github.com/containerd/containerd/cmd/ctr/commands"
@@ -240,10 +241,11 @@
 	s1 := filepath.Join(string(filepath.Separator), "containerd-shim", ns, id, "shim.sock")
 	// this should not error, ctr always get a default ns
 	ctx := namespaces.WithNamespace(gocontext.Background(), ns)
-	s2, _ := shim.SocketAddress(ctx, id)
-
-	for _, socket := range []string{s1, s2} {
-		conn, err := net.Dial("unix", "\x00"+socket)
+	s2, _ := shim.SocketAddress(ctx, context.GlobalString("address"), id)
+	s2 = strings.TrimPrefix(s2, "unix://")
+
+	for _, socket := range []string{s2, "\x00" + s1} {
+		conn, err := net.Dial("unix", socket)
 		if err == nil {
 			client := ttrpc.NewClient(conn)
 
```
