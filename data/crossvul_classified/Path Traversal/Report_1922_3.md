# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 1179-1219 of the vulnerable file.

		}
		if username == "root" {
			// Cannot setup user namespaces with a 1-to-1 mapping; "--root=0:0" is a no-op
			// effectively
			logrus.Warn("User namespaces: root cannot be remapped with itself; user namespaces are OFF")
			return &idtools.IdentityMapping{}, nil
		}
		logrus.Infof("User namespaces: ID ranges will be mapped to subuid/subgid ranges of: %s", username)
		// update remapped root setting now that we have resolved them to actual names
		config.RemappedRoot = fmt.Sprintf("%s:%s", username, groupname)

		mappings, err := idtools.NewIdentityMapping(username)
		if err != nil {
			return nil, errors.Wrap(err, "Can't create ID mappings")
		}
		return mappings, nil
	}
	return &idtools.IdentityMapping{}, nil
}

func setupDaemonRoot(config *config.Config, rootDir string, rootIdentity idtools.Identity) error {
	config.Root = rootDir
	// the docker root metadata directory needs to have execute permissions for all users (g+x,o+x)
	// so that syscalls executing as non-root, operating on subdirectories of the graph root
	// (e.g. mounted layers of a container) can traverse this path.
	// The user namespace support will create subdirectories for the remapped root host uid:gid
	// pair owned by that same uid:gid pair for proper write access to those needed metadata and
	// layer content subtrees.
	if _, err := os.Stat(rootDir); err == nil {
		// root current exists; verify the access bits are correct by setting them
		if err = os.Chmod(rootDir, 0711); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		// no root exists yet, create it 0711 with root:root ownership
		if err := os.MkdirAll(rootDir, 0711); err != nil {
			return err
		}
	}

	// if user namespaces are enabled we will create a subtree underneath the specified root
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1196,7 +1196,7 @@
 	return &idtools.IdentityMapping{}, nil
 }
 
-func setupDaemonRoot(config *config.Config, rootDir string, rootIdentity idtools.Identity) error {
+func setupDaemonRoot(config *config.Config, rootDir string, remappedRoot idtools.Identity) error {
 	config.Root = rootDir
 	// the docker root metadata directory needs to have execute permissions for all users (g+x,o+x)
 	// so that syscalls executing as non-root, operating on subdirectories of the graph root
@@ -1221,10 +1221,16 @@
 	// a new subdirectory with ownership set to the remapped uid/gid (so as to allow
 	// `chdir()` to work for containers namespaced to that uid/gid)
 	if config.RemappedRoot != "" {
-		config.Root = filepath.Join(rootDir, fmt.Sprintf("%d.%d", rootIdentity.UID, rootIdentity.GID))
+		id := idtools.CurrentIdentity()
+		// First make sure the current root dir has the correct perms.
+		if err := idtools.MkdirAllAndChown(config.Root, 0701, id); err != nil {
+			return errors.Wrapf(err, "could not create or set daemon root permissions: %s", config.Root)
+		}
+
+		config.Root = filepath.Join(rootDir, fmt.Sprintf("%d.%d", remappedRoot.UID, remappedRoot.GID))
 		logrus.Debugf("Creating user namespaced daemon root: %s", config.Root)
 		// Create the root directory if it doesn't exist
-		if err := idtools.MkdirAllAndChown(config.Root, 0700, rootIdentity); err != nil {
+		if err := idtools.MkdirAllAndChown(config.Root, 0701, id); err != nil {
 			return fmt.Errorf("Cannot create daemon root: %s: %v", config.Root, err)
 		}
 		// we also need to verify that any pre-existing directories in the path to
@@ -1237,7 +1243,7 @@
 			if dirPath == "/" {
 				break
 			}
-			if !idtools.CanAccess(dirPath, rootIdentity) {
+			if !idtools.CanAccess(dirPath, remappedRoot) {
 				return fmt.Errorf("a subdirectory in your graphroot path (%s) restricts access to the remapped root uid/gid; please fix by allowing 'o+x' permissions on existing directories", config.Root)
 			}
 		}
```
