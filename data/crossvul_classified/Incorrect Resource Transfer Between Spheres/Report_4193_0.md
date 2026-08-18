# CrossVul Fix Pair: Incorrect Resource Transfer Between Spheres in go
**Pair ID:** 4193_0
**Vulnerability Class:** Incorrect Resource Transfer Between Spheres
**CWE:** CWE-669
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4193_0`)

## Vulnerability Information & PoC

## Description
Incorrect Resource Transfer Between Spheres - The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that r...

## Vulnerable Code
```go
Lines 54-94 of the vulnerable file.

	debugFlag            bool
	namespaceFlag        string
	socketFlag           string
	addressFlag          string
	workdirFlag          string
	runtimeRootFlag      string
	criuFlag             string
	systemdCgroupFlag    bool
	containerdBinaryFlag string

	bufPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(nil)
		},
	}
)

func init() {
	flag.BoolVar(&debugFlag, "debug", false, "enable debug output in logs")
	flag.StringVar(&namespaceFlag, "namespace", "", "namespace that owns the shim")
	flag.StringVar(&socketFlag, "socket", "", "abstract socket path to serve")
	flag.StringVar(&addressFlag, "address", "", "grpc address back to main containerd")
	flag.StringVar(&workdirFlag, "workdir", "", "path used to storge large temporary data")
	flag.StringVar(&runtimeRootFlag, "runtime-root", process.RuncRoot, "root directory for the runtime")
	flag.StringVar(&criuFlag, "criu", "", "path to criu binary")
	flag.BoolVar(&systemdCgroupFlag, "systemd-cgroup", false, "set runtime to use systemd-cgroup")
	// currently, the `containerd publish` utility is embedded in the daemon binary.
	// The daemon invokes `containerd-shim -containerd-binary ...` with its own os.Executable() path.
	flag.StringVar(&containerdBinaryFlag, "containerd-binary", "containerd", "path to containerd binary (used for `containerd publish`)")
	flag.Parse()
}

func main() {
	debug.SetGCPercent(40)
	go func() {
		for range time.Tick(30 * time.Second) {
			debug.FreeOSMemory()
		}
	}()

	if debugFlag {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
 func init() {
 	flag.BoolVar(&debugFlag, "debug", false, "enable debug output in logs")
 	flag.StringVar(&namespaceFlag, "namespace", "", "namespace that owns the shim")
-	flag.StringVar(&socketFlag, "socket", "", "abstract socket path to serve")
+	flag.StringVar(&socketFlag, "socket", "", "socket path to serve")
 	flag.StringVar(&addressFlag, "address", "", "grpc address back to main containerd")
 	flag.StringVar(&workdirFlag, "workdir", "", "path used to storge large temporary data")
 	flag.StringVar(&runtimeRootFlag, "runtime-root", process.RuncRoot, "root directory for the runtime")
@@ -202,10 +202,18 @@
 		f.Close()
 		path = "[inherited from parent]"
 	} else {
-		if len(path) > 106 {
-			return errors.Errorf("%q: unix socket path too long (> 106)", path)
-		}
-		l, err = net.Listen("unix", "\x00"+path)
+		const (
+			abstractSocketPrefix = "\x00"
+			socketPathLimit      = 106
+		)
+		p := strings.TrimPrefix(path, "unix://")
+		if len(p) == len(path) {
+			p = abstractSocketPrefix + p
+		}
+		if len(p) > socketPathLimit {
+			return errors.Errorf("%q: unix socket path too long (> %d)", p, socketPathLimit)
+		}
+		l, err = net.Listen("unix", p)
 	}
 	if err != nil {
 		return err
```
