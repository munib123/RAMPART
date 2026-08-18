# CrossVul Fix Pair: Incorrect Resource Transfer Between Spheres in go
**Pair ID:** 4193_4
**Vulnerability Class:** Incorrect Resource Transfer Between Spheres
**CWE:** CWE-669
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4193_4`)

## Vulnerability Information & PoC

## Description
Incorrect Resource Transfer Between Spheres - The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that r...

## Vulnerable Code
```go
Lines 114-154 of the vulnerable file.

	}
	args := []string{
		"-namespace", ns,
		"-id", id,
		"-address", containerdAddress,
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func (s *service) StartShim(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (string, error) {
	cmd, err := newCommand(ctx, id, containerdBinary, containerdAddress, containerdTTRPCAddress)
	if err != nil {
		return "", err
	}
	address, err := shim.SocketAddress(ctx, id)
	if err != nil {
		return "", err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		return "", err
	}
	defer socket.Close()
	f, err := socket.File()
	if err != nil {
		return "", err
	}
	defer f.Close()

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	if err := cmd.Start(); err != nil {
		return "", err
	}
	defer func() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -131,20 +131,26 @@
 	if err != nil {
 		return "", err
 	}
-	address, err := shim.SocketAddress(ctx, id)
+	address, err := shim.SocketAddress(ctx, containerdAddress, id)
 	if err != nil {
 		return "", err
 	}
 	socket, err := shim.NewSocket(address)
 	if err != nil {
+		if !shim.SocketEaddrinuse(err) {
+			return "", err
+		}
+		if err := shim.RemoveSocket(address); err != nil {
+			return "", errors.Wrap(err, "remove already used socket")
+		}
+		if socket, err = shim.NewSocket(address); err != nil {
+			return "", err
+		}
+	}
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
 
@@ -153,6 +159,7 @@
 	}
 	defer func() {
 		if err != nil {
+			_ = shim.RemoveSocket(address)
 			cmd.Process.Kill()
 		}
 	}()
@@ -551,6 +558,9 @@
 func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*ptypes.Empty, error) {
 	s.cancel()
 	close(s.events)
+	if address, err := shim.ReadAddress("address"); err == nil {
+		_ = shim.RemoveSocket(address)
+	}
 	return empty, nil
 }
 
```
