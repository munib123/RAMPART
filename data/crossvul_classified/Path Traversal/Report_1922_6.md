# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_6
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_6`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 71-116 of the vulnerable file.

var (
	logger = logrus.WithField("storage-driver", driverName)
)

func init() {
	graphdriver.Register(driverName, Init)
}

// Init returns the naive diff driver for fuse-overlayfs.
// If fuse-overlayfs is not supported on the host, the error
// graphdriver.ErrNotSupported is returned.
func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {
	if _, err := exec.LookPath(binary); err != nil {
		logger.Error(err)
		return nil, graphdriver.ErrNotSupported
	}
	if !kernel.CheckKernelVersion(4, 18, 0) {
		return nil, graphdriver.ErrNotSupported
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if err != nil {
		return nil, err
	}
	// Create the driver home dir
	if err := idtools.MkdirAllAndChown(path.Join(home, linkDir), 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return nil, err
	}

	d := &Driver{
		home:    home,
		uidMaps: uidMaps,
		gidMaps: gidMaps,
		ctr:     graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicFUSE)),
		locker:  locker.New(),
	}

	d.naiveDiff = graphdriver.NewNaiveDiffDriver(d, uidMaps, gidMaps)

	return d, nil
}

func (d *Driver) String() string {
	return driverName
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,12 +88,7 @@
 		return nil, graphdriver.ErrNotSupported
 	}
 
-	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
-	if err != nil {
-		return nil, err
-	}
-	// Create the driver home dir
-	if err := idtools.MkdirAllAndChown(path.Join(home, linkDir), 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+	if err := idtools.MkdirAllAndChown(path.Join(home, linkDir), 0701, idtools.CurrentIdentity()); err != nil {
 		return nil, err
 	}
 
@@ -178,10 +173,11 @@
 	}
 	root := idtools.Identity{UID: rootUID, GID: rootGID}
 
-	if err := idtools.MkdirAllAndChown(path.Dir(dir), 0700, root); err != nil {
-		return err
-	}
-	if err := idtools.MkdirAndChown(dir, 0700, root); err != nil {
+	currentID := idtools.CurrentIdentity()
+	if err := idtools.MkdirAllAndChown(path.Dir(dir), 0701, currentID); err != nil {
+		return err
+	}
+	if err := idtools.MkdirAndChown(dir, 0701, currentID); err != nil {
 		return err
 	}
 
@@ -215,7 +211,7 @@
 		return nil
 	}
 
-	if err := idtools.MkdirAndChown(path.Join(dir, workDirName), 0700, root); err != nil {
+	if err := idtools.MkdirAndChown(path.Join(dir, workDirName), 0701, currentID); err != nil {
 		return err
 	}
 
```
