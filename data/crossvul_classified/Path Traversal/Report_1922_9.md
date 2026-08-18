# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_9
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_9`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 21-62 of the vulnerable file.

	// CopyDir defines the copy method to use.
	CopyDir = dirCopy
)

func init() {
	graphdriver.Register("vfs", Init)
}

// Init returns a new VFS driver.
// This sets the home directory for the driver and returns NaiveDiffDriver.
func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {
	d := &Driver{
		home:      home,
		idMapping: idtools.NewIDMappingsFromMaps(uidMaps, gidMaps),
	}

	if err := d.parseOptions(options); err != nil {
		return nil, err
	}

	rootIDs := d.idMapping.RootPair()
	if err := idtools.MkdirAllAndChown(home, 0700, rootIDs); err != nil {
		return nil, err
	}

	setupDriverQuota(d)

	if size := d.getQuotaOpt(); !d.quotaSupported() && size > 0 {
		return nil, quota.ErrQuotaNotSupported
	}

	return graphdriver.NewNaiveDiffDriver(d, uidMaps, gidMaps), nil
}

// Driver holds information about the driver, home directory of the driver.
// Driver implements graphdriver.ProtoDriver. It uses only basic vfs operations.
// In order to support layering, files are copied from the parent layer into the new layer. There is no copy-on-write support.
// Driver must be wrapped in NaiveDiffDriver to be used as a graphdriver.Driver
type Driver struct {
	driverQuota
	home      string
	idMapping *idtools.IdentityMapping
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,8 +38,7 @@
 		return nil, err
 	}
 
-	rootIDs := d.idMapping.RootPair()
-	if err := idtools.MkdirAllAndChown(home, 0700, rootIDs); err != nil {
+	if err := idtools.MkdirAllAndChown(home, 0701, idtools.CurrentIdentity()); err != nil {
 		return nil, err
 	}
 
@@ -141,7 +140,7 @@
 func (d *Driver) create(id, parent string, size uint64) error {
 	dir := d.dir(id)
 	rootIDs := d.idMapping.RootPair()
-	if err := idtools.MkdirAllAndChown(filepath.Dir(dir), 0700, rootIDs); err != nil {
+	if err := idtools.MkdirAllAndChown(filepath.Dir(dir), 0701, idtools.CurrentIdentity()); err != nil {
 		return err
 	}
 	if err := idtools.MkdirAndChown(dir, 0755, rootIDs); err != nil {
```
