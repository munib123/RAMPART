# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 177-219 of the vulnerable file.

		if retErr != nil {
			if err := daemon.cleanupContainer(ctr, true, true); err != nil {
				logrus.Errorf("failed to cleanup container on create error: %v", err)
			}
		}
	}()

	if err := daemon.setSecurityOptions(ctr, opts.params.HostConfig); err != nil {
		return nil, err
	}

	ctr.HostConfig.StorageOpt = opts.params.HostConfig.StorageOpt

	// Set RWLayer for container after mount labels have been set
	rwLayer, err := daemon.imageService.CreateLayer(ctr, setupInitLayer(daemon.idMapping))
	if err != nil {
		return nil, errdefs.System(err)
	}
	ctr.RWLayer = rwLayer

	rootIDs := daemon.idMapping.RootPair()

	if err := idtools.MkdirAndChown(ctr.Root, 0700, rootIDs); err != nil {
		return nil, err
	}
	if err := idtools.MkdirAndChown(ctr.CheckpointDir(), 0700, rootIDs); err != nil {
		return nil, err
	}

	if err := daemon.setHostConfig(ctr, opts.params.HostConfig); err != nil {
		return nil, err
	}

	if err := daemon.createContainerOSSpecificSettings(ctr, opts.params.Config, opts.params.HostConfig); err != nil {
		return nil, err
	}

	var endpointsConfigs map[string]*networktypes.EndpointSettings
	if opts.params.NetworkingConfig != nil {
		endpointsConfigs = opts.params.NetworkingConfig.EndpointsConfig
	}
	// Make sure NetworkMode has an acceptable value. We do this to ensure
	// backwards API compatibility.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,12 +194,10 @@
 	}
 	ctr.RWLayer = rwLayer
 
-	rootIDs := daemon.idMapping.RootPair()
-
-	if err := idtools.MkdirAndChown(ctr.Root, 0700, rootIDs); err != nil {
-		return nil, err
-	}
-	if err := idtools.MkdirAndChown(ctr.CheckpointDir(), 0700, rootIDs); err != nil {
+	if err := idtools.MkdirAndChown(ctr.Root, 0701, idtools.CurrentIdentity()); err != nil {
+		return nil, err
+	}
+	if err := idtools.MkdirAndChown(ctr.CheckpointDir(), 0700, idtools.CurrentIdentity()); err != nil {
 		return nil, err
 	}
 
```
