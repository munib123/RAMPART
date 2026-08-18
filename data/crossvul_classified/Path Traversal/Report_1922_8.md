# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_8
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_8`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 148-193 of the vulnerable file.

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
			return nil, overlayutils.ErrDTypeNotSupported("overlay2", backingFs)
		}
		// allow running without d_type only for existing setups (#27443)
		logger.Warn(overlayutils.ErrDTypeNotSupported("overlay2", backingFs))
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
		home:          home,
		uidMaps:       uidMaps,
		gidMaps:       gidMaps,
		ctr:           graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicOverlay)),
		supportsDType: supportsDType,
		locker:        locker.New(),
		options:       *opts,
	}

	d.naiveDiff = graphdriver.NewNaiveDiffDriver(d, uidMaps, gidMaps)

	if backingFs == "xfs" {
		// Try to enable project quota support over xfs.
		if d.quotaCtl, err = quota.NewControl(home); err == nil {
			projectQuotaSupported = true
		} else if opts.quota.Size > 0 {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,12 +165,7 @@
 		logger.Warn(overlayutils.ErrDTypeNotSupported("overlay2", backingFs))
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
 
@@ -339,11 +334,12 @@
 		return err
 	}
 	root := idtools.Identity{UID: rootUID, GID: rootGID}
-
-	if err := idtools.MkdirAllAndChown(path.Dir(dir), 0700, root); err != nil {
-		return err
-	}
-	if err := idtools.MkdirAndChown(dir, 0700, root); err != nil {
+	current := idtools.CurrentIdentity()
+
+	if err := idtools.MkdirAllAndChown(path.Dir(dir), 0701, current); err != nil {
+		return err
+	}
+	if err := idtools.MkdirAndChown(dir, 0701, current); err != nil {
 		return err
 	}
 
```
