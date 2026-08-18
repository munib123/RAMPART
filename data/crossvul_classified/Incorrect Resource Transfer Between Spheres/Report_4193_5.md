# CrossVul Fix Pair: Incorrect Resource Transfer Between Spheres in go
**Pair ID:** 4193_5
**Vulnerability Class:** Incorrect Resource Transfer Between Spheres
**CWE:** CWE-669
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4193_5`)

## Vulnerability Information & PoC

## Description
Incorrect Resource Transfer Between Spheres - The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that r...

## Vulnerable Code
```go
Lines 8-48 of the vulnerable file.

   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package v2

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/oom"
	oomv1 "github.com/containerd/containerd/pkg/oom/v1"
	oomv2 "github.com/containerd/containerd/pkg/oom/v2"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime/v2/runc"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/containerd/runtime/v2/shim"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,6 @@
 	"os"
 	"os/exec"
 	"path/filepath"
-	"strings"
 	"sync"
 	"syscall"
 	"time"
@@ -105,6 +104,10 @@
 		return nil, errors.Wrap(err, "failed to initialized platform behavior")
 	}
 	go s.forward(ctx, publisher)
+
+	if address, err := shim.ReadAddress("address"); err == nil {
+		s.shimAddress = address
+	}
 	return s, nil
 }
 
@@ -124,7 +127,8 @@
 
 	containers map[string]*runc.Container
 
-	cancel func()
+	shimAddress string
+	cancel      func()
 }
 
 func newCommand(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (*exec.Cmd, error) {
@@ -183,30 +187,48 @@
 			break
 		}
 	}
-	address, err := shim.SocketAddress(ctx, grouping)
+	address, err := shim.SocketAddress(ctx, containerdAddress, grouping)
 	if err != nil {
 		return "", err
 	}
+
 	socket, err := shim.NewSocket(address)
 	if err != nil {
-		if strings.Contains(err.Error(), "address already in use") {
+		// the only time where this would happen is if there is a bug and the socket
+		// was not cleaned up in the cleanup method of the shim or we are using the
+		// grouping functionality where the new process should be run with the same
+		// shim as an existing container
+		if !shim.SocketEaddrinuse(err) {
+			return "", errors.Wrap(err, "create new shim socket")
+		}
+		if shim.CanConnect(address) {
 			if err := shim.WriteAddress("address", address); err != nil {
-				return "", err
+				return "", errors.Wrap(err, "write existing socket for shim")
 			}
 			return address, nil
 		}
+		if err := shim.RemoveSocket(address); err != nil {
+			return "", errors.Wrap(err, "remove pre-existing socket")
+		}
+		if socket, err = shim.NewSocket(address); err != nil {
+			return "", errors.Wrap(err, "try create new shim socket 2x")
+		}
+	}
+	defer func() {
+		if retErr != nil {
+			socket.Close()
+			_ = shim.RemoveSocket(address)
+		}
+	}()
+	f, err := socket.File()
+	if err != nil {
 		return "", err
 	}
-	defer socket.Close()
-	f, err := socket.File()
-	if err != nil {
-		return "", err
-	}
-	defer f.Close()
 
 	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
 
 	if err := cmd.Start(); err != nil {
+		f.Close()
 		return "", err
 	}
 	defer func() {
@@ -273,7 +295,6 @@
 	if err != nil {
 		return nil, err
 	}
-
 	runtime, err := runc.ReadRuntime(path)
 	if err != nil {
 		return nil, err
@@ -652,7 +673,9 @@
 	if s.platform != nil {
 		s.platform.Close()
 	}
-
+	if s.shimAddress != "" {
+		_ = shim.RemoveSocket(s.shimAddress)
+	}
 	return empty, nil
 }
 
```
