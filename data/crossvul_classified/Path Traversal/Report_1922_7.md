# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_7
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_7`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 139-182 of the vulnerable file.

	fsMagic, err := graphdriver.GetFSMagic(testdir)
	if err != nil {
		return nil, err
	}
	if fsName, ok := graphdriver.FsNames[fsMagic]; ok {
		backingFs = fsName
	}

	supportsDType, err := fsutils.SupportsDType(testdir)
	if err != nil {
		return nil, err
	}
	if !supportsDType {
		if !graphdriver.IsInitialized(home) {
			return nil, overlayutils.ErrDTypeNotSupported("overlay", backingFs)
		}
		// allow running without d_type only for existing setups (#27443)
		logrus.WithField("storage-driver", "overlay").Warn(overlayutils.ErrDTypeNotSupported("overlay", backingFs))
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if err != nil {
		return nil, err
	}
	// Create the driver home dir
	if err := idtools.MkdirAllAndChown(home, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return nil, err
	}

	d := &Driver{
		home:          home,
		uidMaps:       uidMaps,
		gidMaps:       gidMaps,
		ctr:           graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicOverlay)),
		supportsDType: supportsDType,
		locker:        locker.New(),
	}

	return NaiveDiffDriverWithApply(d, uidMaps, gidMaps), nil
}

func parseOptions(options []string) (*overlayOptions, error) {
	o := &overlayOptions{}
	for _, option := range options {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,12 +156,8 @@
 		logrus.WithField("storage-driver", "overlay").Warn(overlayutils.ErrDTypeNotSupported("overlay", backingFs))
 	}
 
-	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
-	if err != nil {
-		return nil, err
-	}
 	// Create the driver home dir
-	if err := idtools.MkdirAllAndChown(home, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+	if err := idtools.MkdirAllAndChown(home, 0701, idtools.CurrentIdentity()); err != nil {
 		return nil, err
 	}
 
@@ -265,10 +261,11 @@
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
 
@@ -281,6 +278,7 @@
 
 	// Toplevel images are just a "root" dir
 	if parent == "" {
+		// This must be 0755 otherwise unprivileged users will in the container will not be able to read / in the container
 		return idtools.MkdirAndChown(path.Join(dir, "root"), 0755, root)
 	}
 
@@ -301,7 +299,7 @@
 		if err := idtools.MkdirAndChown(path.Join(dir, "work"), 0700, root); err != nil {
 			return err
 		}
-		return ioutil.WriteFile(path.Join(dir, "lower-id"), []byte(parent), 0666)
+		return ioutil.WriteFile(path.Join(dir, "lower-id"), []byte(parent), 0600)
 	}
 
 	// Otherwise, copy the upper and the lower-id from the parent
@@ -311,7 +309,7 @@
 		return err
 	}
 
-	if err := ioutil.WriteFile(path.Join(dir, "lower-id"), lowerID, 0666); err != nil {
+	if err := ioutil.WriteFile(path.Join(dir, "lower-id"), lowerID, 0600); err != nil {
 		return err
 	}
 
```
