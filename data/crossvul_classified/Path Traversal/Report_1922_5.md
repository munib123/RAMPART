# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 53-97 of the vulnerable file.

func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {

	// Perform feature detection on /var/lib/docker/btrfs if it's an existing directory.
	// This covers situations where /var/lib/docker/btrfs is a mount, and on a different
	// filesystem than /var/lib/docker.
	// If the path does not exist, fall back to using /var/lib/docker for feature detection.
	testdir := home
	if _, err := os.Stat(testdir); os.IsNotExist(err) {
		testdir = filepath.Dir(testdir)
	}

	fsMagic, err := graphdriver.GetFSMagic(testdir)
	if err != nil {
		return nil, err
	}

	if fsMagic != graphdriver.FsMagicBtrfs {
		return nil, graphdriver.ErrPrerequisites
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if err != nil {
		return nil, err
	}
	if err := idtools.MkdirAllAndChown(home, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return nil, err
	}

	opt, userDiskQuota, err := parseOptions(options)
	if err != nil {
		return nil, err
	}

	// For some reason shared mount propagation between a container
	// and the host does not work for btrfs, and a remedy is to bind
	// mount graphdriver home to itself (even without changing the
	// propagation mode).
	err = mount.MakeMount(home)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to make %s a mount", home)
	}

	driver := &Driver{
		home:    home,
		uidMaps: uidMaps,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,11 +70,7 @@
 		return nil, graphdriver.ErrPrerequisites
 	}
 
-	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
-	if err != nil {
-		return nil, err
-	}
-	if err := idtools.MkdirAllAndChown(home, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+	if err := idtools.MkdirAllAndChown(home, 0701, idtools.CurrentIdentity()); err != nil {
 		return nil, err
 	}
 
@@ -525,7 +521,7 @@
 	if err != nil {
 		return err
 	}
-	if err := idtools.MkdirAllAndChown(subvolumes, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+	if err := idtools.MkdirAllAndChown(subvolumes, 0701, idtools.CurrentIdentity()); err != nil {
 		return err
 	}
 	if parent == "" {
@@ -560,7 +556,7 @@
 		if err := d.setStorageSize(path.Join(subvolumes, id), driver); err != nil {
 			return err
 		}
-		if err := idtools.MkdirAllAndChown(quotas, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
+		if err := idtools.MkdirAllAndChown(quotas, 0700, idtools.CurrentIdentity()); err != nil {
 			return err
 		}
 		if err := ioutil.WriteFile(path.Join(quotas, id), []byte(fmt.Sprint(driver.options.size)), 0644); err != nil {
```
