# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_4
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_4`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 26-66 of the vulnerable file.

	w.driver.debug("ContainerStarted", "%s", id)
	info, err := w.client.InspectContainer(id)
	if err != nil {
		w.driver.warn("ContainerStarted", "error inspecting container %s: %s", id, err)
		return
	}
	// check that it's on our network
	for _, net := range info.NetworkSettings.Networks {
		network, err := w.driver.findNetworkInfo(net.NetworkID)
		if err != nil {
			w.driver.warn("ContainerStarted", "unable to find network %s info: %s", net.NetworkID, err)
			continue
		}
		if network.isOurs {
			if w.driver.dns {
				fqdn := fmt.Sprintf("%s.%s", info.Config.Hostname, info.Config.Domainname)
				if err := w.weave.RegisterWithDNS(id, fqdn, net.IPAddress); err != nil {
					w.driver.warn("ContainerStarted", "unable to register %s with weaveDNS: %s", id, err)
				}
			}
			rootDir := "/"
			if w.driver.isPluginV2 {
				// We bind mount host's /proc to /host/proc for plugin-v2
				rootDir = "/host"
			}
			netNSPath := weavenet.NSPathByPidWithRoot(rootDir, info.State.Pid)
			if err := weavenet.WithNetNSByPath(netNSPath, func() error {
				return weavenet.ConfigureARP(weavenet.VethName, rootDir)
			}); err != nil {
				w.driver.warn("ContainerStarted", "unable to configure interfaces: %s", err)
			}
		}
	}
}

func (w *watcher) ContainerDied(id string) {
	// don't need to do this as WeaveDNS removes names on container died anyway
	// (note by the time we get this event we can't see the EndpointID)
}

func (w *watcher) ContainerDestroyed(id string) {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,14 +43,9 @@
 					w.driver.warn("ContainerStarted", "unable to register %s with weaveDNS: %s", id, err)
 				}
 			}
-			rootDir := "/"
-			if w.driver.isPluginV2 {
-				// We bind mount host's /proc to /host/proc for plugin-v2
-				rootDir = "/host"
-			}
-			netNSPath := weavenet.NSPathByPidWithRoot(rootDir, info.State.Pid)
+			netNSPath := weavenet.NSPathByPidWithProc(w.driver.procPath, info.State.Pid)
 			if err := weavenet.WithNetNSByPath(netNSPath, func() error {
-				return weavenet.ConfigureARP(weavenet.VethName, rootDir)
+				return weavenet.ConfigureARP(weavenet.VethName, w.driver.procPath)
 			}); err != nil {
 				w.driver.warn("ContainerStarted", "unable to configure interfaces: %s", err)
 			}
```
