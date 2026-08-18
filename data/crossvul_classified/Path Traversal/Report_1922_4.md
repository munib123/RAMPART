# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 112-155 of the vulnerable file.

	case graphdriver.FsMagicAufs, graphdriver.FsMagicBtrfs, graphdriver.FsMagicEcryptfs:
		logger.Errorf("AUFS is not supported over %s", backingFs)
		return nil, graphdriver.ErrIncompatibleFS
	}

	paths := []string{
		"mnt",
		"diff",
		"layers",
	}

	a := &Driver{
		root:      root,
		uidMaps:   uidMaps,
		gidMaps:   gidMaps,
		pathCache: make(map[string]string),
		ctr:       graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicAufs)),
		locker:    locker.New(),
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if err != nil {
		return nil, err
	}
	// Create the root aufs driver dir
	if err := idtools.MkdirAllAndChown(root, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return nil, err
	}

	// Populate the dir structure
	for _, p := range paths {
		if err := idtools.MkdirAllAndChown(path.Join(root, p), 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
			return nil, err
		}
	}

	for _, path := range []string{"mnt", "diff"} {
		p := filepath.Join(root, path)
		entries, err := ioutil.ReadDir(p)
		if err != nil {
			logger.WithError(err).WithField("dir", p).Error("error reading dir entries")
			continue
		}
		for _, entry := range entries {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,18 +129,15 @@
 		locker:    locker.New(),
 	}
 
-	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
-	if err != nil {
-		return nil, err
-	}
+	currentID := idtools.CurrentIdentity()
 	// Create the root aufs driver dir
-	if err := idtools.MkdirAllAndChown(root, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+	if err := idtools.MkdirAllAndChown(root, 0701, currentID); err != nil {
 		return nil, err
 	}
 
 	// Populate the dir structure
 	for _, p := range paths {
-		if err := idtools.MkdirAllAndChown(path.Join(root, p), 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+		if err := idtools.MkdirAllAndChown(path.Join(root, p), 0701, currentID); err != nil {
 			return nil, err
 		}
 	}
```
