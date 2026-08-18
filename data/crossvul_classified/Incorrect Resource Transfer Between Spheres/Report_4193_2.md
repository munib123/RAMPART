# CrossVul Fix Pair: Incorrect Resource Transfer Between Spheres in go
**Pair ID:** 4193_2
**Vulnerability Class:** Incorrect Resource Transfer Between Spheres
**CWE:** CWE-669
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4193_2`)

## Vulnerability Information & PoC

## Description
Incorrect Resource Transfer Between Spheres - The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that r...

## Vulnerable Code
```go
Lines 74-114 of the vulnerable file.

		id:      id,
		path:    path,
		workDir: workDir,
	}, err
}

type bundle struct {
	id      string
	path    string
	workDir string
}

// ShimOpt specifies shim options for initialization and connection
type ShimOpt func(*bundle, string, *runctypes.RuncOptions) (shim.Config, client.Opt)

// ShimRemote is a ShimOpt for connecting and starting a remote shim
func ShimRemote(c *Config, daemonAddress, cgroup string, exitHandler func()) ShimOpt {
	return func(b *bundle, ns string, ropts *runctypes.RuncOptions) (shim.Config, client.Opt) {
		config := b.shimConfig(ns, c, ropts)
		return config,
			client.WithStart(c.Shim, b.shimAddress(ns), daemonAddress, cgroup, c.ShimDebug, exitHandler)
	}
}

// ShimLocal is a ShimOpt for using an in process shim implementation
func ShimLocal(c *Config, exchange *exchange.Exchange) ShimOpt {
	return func(b *bundle, ns string, ropts *runctypes.RuncOptions) (shim.Config, client.Opt) {
		return b.shimConfig(ns, c, ropts), client.WithLocal(exchange)
	}
}

// ShimConnect is a ShimOpt for connecting to an existing remote shim
func ShimConnect(c *Config, onClose func()) ShimOpt {
	return func(b *bundle, ns string, ropts *runctypes.RuncOptions) (shim.Config, client.Opt) {
		return b.shimConfig(ns, c, ropts), client.WithConnect(b.decideShimAddress(ns), onClose)
	}
}

// NewShimClient connects to the shim managing the bundle and tasks creating it if needed
func (b *bundle) NewShimClient(ctx context.Context, namespace string, getClientOpts ShimOpt, runcOpts *runctypes.RuncOptions) (*client.Client, error) {
	cfg, opt := getClientOpts(b, namespace, runcOpts)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,7 +91,7 @@
 	return func(b *bundle, ns string, ropts *runctypes.RuncOptions) (shim.Config, client.Opt) {
 		config := b.shimConfig(ns, c, ropts)
 		return config,
-			client.WithStart(c.Shim, b.shimAddress(ns), daemonAddress, cgroup, c.ShimDebug, exitHandler)
+			client.WithStart(c.Shim, b.shimAddress(ns, daemonAddress), daemonAddress, cgroup, c.ShimDebug, exitHandler)
 	}
 }
 
@@ -117,6 +117,11 @@
 
 // Delete deletes the bundle from disk
 func (b *bundle) Delete() error {
+	address, _ := b.loadAddress()
+	if address != "" {
+		// we don't care about errors here
+		client.RemoveSocket(address)
+	}
 	err := atomicDelete(b.path)
 	if err == nil {
 		return atomicDelete(b.workDir)
@@ -133,9 +138,11 @@
 	return filepath.Join(string(filepath.Separator), "containerd-shim", namespace, b.id, "shim.sock")
 }
 
-func (b *bundle) shimAddress(namespace string) string {
-	d := sha256.Sum256([]byte(filepath.Join(namespace, b.id)))
-	return filepath.Join(string(filepath.Separator), "containerd-shim", fmt.Sprintf("%x.sock", d))
+const socketRoot = "/run/containerd"
+
+func (b *bundle) shimAddress(namespace, socketPath string) string {
+	d := sha256.Sum256([]byte(filepath.Join(socketPath, namespace, b.id)))
+	return fmt.Sprintf("unix://%s/%x", filepath.Join(socketRoot, "s"), d)
 }
 
 func (b *bundle) loadAddress() (string, error) {
```
