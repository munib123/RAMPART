# CrossVul Fix Pair: Incorrect Resource Transfer Between Spheres in go
**Pair ID:** 4193_3
**Vulnerability Class:** Incorrect Resource Transfer Between Spheres
**CWE:** CWE-669
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4193_3`)

## Vulnerability Information & PoC

## Description
Incorrect Resource Transfer Between Spheres - The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that r...

## Vulnerable Code
```go
Lines 42-82 of the vulnerable file.

	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/dialer"
	v1 "github.com/containerd/containerd/runtime/v1"
	"github.com/containerd/containerd/runtime/v1/shim"
	shimapi "github.com/containerd/containerd/runtime/v1/shim/v1"
	"github.com/containerd/containerd/sys"
	ptypes "github.com/gogo/protobuf/types"
)

var empty = &ptypes.Empty{}

// Opt is an option for a shim client configuration
type Opt func(context.Context, shim.Config) (shimapi.ShimService, io.Closer, error)

// WithStart executes a new shim process
func WithStart(binary, address, daemonAddress, cgroup string, debug bool, exitHandler func()) Opt {
	return func(ctx context.Context, config shim.Config) (_ shimapi.ShimService, _ io.Closer, err error) {
		socket, err := newSocket(address)
		if err != nil {
			return nil, nil, err
		}
		defer socket.Close()
		f, err := socket.File()
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to get fd for socket %s", address)
		}
		defer f.Close()

		stdoutCopy := ioutil.Discard
		stderrCopy := ioutil.Discard
		stdoutLog, err := v1.OpenShimStdoutLog(ctx, config.WorkDir)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create stdout log")
		}

		stderrLog, err := v1.OpenShimStderrLog(ctx, config.WorkDir)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create stderr log")
		}
		if debug {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,9 +59,17 @@
 	return func(ctx context.Context, config shim.Config) (_ shimapi.ShimService, _ io.Closer, err error) {
 		socket, err := newSocket(address)
 		if err != nil {
-			return nil, nil, err
-		}
-		defer socket.Close()
+			if !eaddrinuse(err) {
+				return nil, nil, err
+			}
+			if err := RemoveSocket(address); err != nil {
+				return nil, nil, errors.Wrap(err, "remove already used socket")
+			}
+			if socket, err = newSocket(address); err != nil {
+				return nil, nil, err
+			}
+		}
+
 		f, err := socket.File()
 		if err != nil {
 			return nil, nil, errors.Wrapf(err, "failed to get fd for socket %s", address)
@@ -108,6 +116,8 @@
 			if stderrLog != nil {
 				stderrLog.Close()
 			}
+			socket.Close()
+			RemoveSocket(address)
 		}()
 		log.G(ctx).WithFields(logrus.Fields{
 			"pid":     cmd.Process.Pid,
@@ -140,6 +150,26 @@
 		}
 		return c, clo, nil
 	}
+}
+
+func eaddrinuse(err error) bool {
+	cause := errors.Cause(err)
+	netErr, ok := cause.(*net.OpError)
+	if !ok {
+		return false
+	}
+	if netErr.Op != "listen" {
+		return false
+	}
+	syscallErr, ok := netErr.Err.(*os.SyscallError)
+	if !ok {
+		return false
+	}
+	errno, ok := syscallErr.Err.(syscall.Errno)
+	if !ok {
+		return false
+	}
+	return errno == syscall.EADDRINUSE
 }
 
 // setupOOMScore gets containerd's oom score and adds +1 to it
@@ -214,31 +244,73 @@
 	return os.Rename(tempPath, path)
 }
 
+const (
+	abstractSocketPrefix = "\x00"
+	socketPathLimit      = 106
+)
+
+type socket string
+
+func (s socket) isAbstract() bool {
+	return !strings.HasPrefix(string(s), "unix://")
+}
+
+func (s socket) path() string {
+	path := strings.TrimPrefix(string(s), "unix://")
+	// if there was no trim performed, we assume an abstract socket
+	if len(path) == len(s) {
+		path = abstractSocketPrefix + path
+	}
+	return path
+}
+
 func newSocket(address string) (*net.UnixListener, error) {
-	if len(address) > 106 {
-		return nil, errors.Errorf("%q: unix socket path too long (> 106)", address)
-	}
-	l, err := net.Listen("unix", "\x00"+address)
-	if err != nil {
-		return nil, errors.Wrapf(err, "failed to listen to abstract unix socket %q", address)
+	if len(address) > socketPathLimit {
+		return nil, errors.Errorf("%q: unix socket path too long (> %d)", address, socketPathLimit)
+	}
+	var (
+		sock = socket(address)
+		path = sock.path()
+	)
+	if !sock.isAbstract() {
+		if err := os.MkdirAll(filepath.Dir(path), 0600); err != nil {
+			return nil, errors.Wrapf(err, "%s", path)
+		}
+	}
+	l, err := net.Listen("unix", path)
+	if err != nil {
+		return nil, errors.Wrapf(err, "failed to listen to unix socket %q (abstract: %t)", address, sock.isAbstract())
+	}
+	if err := os.Chmod(path, 0600); err != nil {
+		l.Close()
+		return nil, err
 	}
 
 	return l.(*net.UnixListener), nil
+}
+
+// RemoveSocket removes the socket at the specified address if
+// it exists on the filesystem
+func RemoveSocket(address string) error {
+	sock := socket(address)
+	if !sock.isAbstract() {
+		return os.Remove(sock.path())
+	}
+	return nil
 }
 
 func connect(address string, d func(string, time.Duration) (net.Conn, error)) (net.Conn, error) {
 	return d(address, 100*time.Second)
 }
 
-func annonDialer(address string, timeout time.Duration) (net.Conn, error) {
-	address = strings.TrimPrefix(address, "unix://")
-	return dialer.Dialer("\x00"+address, timeout)
+func anonDialer(address string, timeout time.Duration) (net.Conn, error) {
+	return dialer.Dialer(socket(address).path(), timeout)
 }
 
 // WithConnect connects to an existing shim
 func WithConnect(address string, onClose func()) Opt {
 	return func(ctx context.Context, config shim.Config) (shimapi.ShimService, io.Closer, error) {
-		conn, err := connect(address, annonDialer)
+		conn, err := connect(address, anonDialer)
 		if err != nil {
 			return nil, nil, err
 		}
```
