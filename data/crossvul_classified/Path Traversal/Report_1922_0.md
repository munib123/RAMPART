# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 1922_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1922_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 449-470 of the vulnerable file.

	if err != nil {
		return err
	}
	*sboxOptions = append(*sboxOptions, libnetwork.OptionResolvConfPath(container.ResolvConfPath))
	return nil
}

func (daemon *Daemon) initializeNetworkingPaths(container *container.Container, nc *container.Container) error {
	container.HostnamePath = nc.HostnamePath
	container.HostsPath = nc.HostsPath
	container.ResolvConfPath = nc.ResolvConfPath
	return nil
}

func (daemon *Daemon) setupContainerMountsRoot(c *container.Container) error {
	// get the root mount path so we can make it unbindable
	p, err := c.MountsResourcePath("")
	if err != nil {
		return err
	}
	return idtools.MkdirAllAndChown(p, 0700, daemon.idMapping.RootPair())
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -466,5 +466,5 @@
 	if err != nil {
 		return err
 	}
-	return idtools.MkdirAllAndChown(p, 0700, daemon.idMapping.RootPair())
-}
+	return idtools.MkdirAllAndChown(p, 0701, idtools.CurrentIdentity())
+}
```
