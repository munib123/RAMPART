# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 778-818 of the vulnerable file.

	// Verify the platform is supported as a daemon
	if !platformSupported {
		return nil, errSystemNotSupported
	}

	// Validate platform-specific requirements
	if err := checkSystem(); err != nil {
		return nil, err
	}

	idMapping, err := setupRemappedRoot(config)
	if err != nil {
		return nil, err
	}
	rootIDs := idMapping.RootPair()
	if err := setupDaemonProcess(config); err != nil {
		return nil, err
	}

	// set up the tmpDir to use a canonical path
	tmp, err := prepareTempDir(config.Root, rootIDs)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the TempDir under %s: %s", config.Root, err)
	}
	realTmp, err := fileutils.ReadSymlinkedDirectory(tmp)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the full path to the TempDir (%s): %s", tmp, err)
	}
	if isWindows {
		if _, err := os.Stat(realTmp); err != nil && os.IsNotExist(err) {
			if err := system.MkdirAll(realTmp, 0700); err != nil {
				return nil, fmt.Errorf("Unable to create the TempDir (%s): %s", realTmp, err)
			}
		}
		os.Setenv("TEMP", realTmp)
		os.Setenv("TMP", realTmp)
	} else {
		os.Setenv("TMPDIR", realTmp)
	}

	d := &Daemon{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -795,7 +795,7 @@
 	}
 
 	// set up the tmpDir to use a canonical path
-	tmp, err := prepareTempDir(config.Root, rootIDs)
+	tmp, err := prepareTempDir(config.Root)
 	if err != nil {
 		return nil, fmt.Errorf("Unable to get the TempDir under %s: %s", config.Root, err)
 	}
@@ -861,7 +861,7 @@
 	}
 
 	daemonRepo := filepath.Join(config.Root, "containers")
-	if err := idtools.MkdirAllAndChown(daemonRepo, 0700, rootIDs); err != nil {
+	if err := idtools.MkdirAllAndChown(daemonRepo, 0701, idtools.CurrentIdentity()); err != nil {
 		return nil, err
 	}
 
@@ -1374,7 +1374,7 @@
 // prepareTempDir prepares and returns the default directory to use
 // for temporary files.
 // If it doesn't exist, it is created. If it exists, its content is removed.
-func prepareTempDir(rootDir string, rootIdentity idtools.Identity) (string, error) {
+func prepareTempDir(rootDir string) (string, error) {
 	var tmpDir string
 	if tmpDir = os.Getenv("DOCKER_TMPDIR"); tmpDir == "" {
 		tmpDir = filepath.Join(rootDir, "tmp")
@@ -1392,9 +1392,7 @@
 			}
 		}
 	}
-	// We don't remove the content of tmpdir if it's not the default,
-	// it may hold things that do not belong to us.
-	return tmpDir, idtools.MkdirAllAndChown(tmpDir, 0700, rootIdentity)
+	return tmpDir, idtools.MkdirAllAndChown(tmpDir, 0700, idtools.CurrentIdentity())
 }
 
 func (daemon *Daemon) setGenericResources(conf *config.Config) error {
```
