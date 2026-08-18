# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_3
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_3`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 22-62 of the vulnerable file.

	MulticastOption = "works.weave.multicast"
)

type network struct {
	isOurs            bool
	hasMulticastRoute bool
}

type driver struct {
	sync.RWMutex
	name  string
	scope string
	// Docker API is not available for plugin-v2
	docker     *docker.Client
	dns        bool
	isPluginV2 bool
	// Enable multicast regardless whether multicast opt is passed to Docker;
	// used only by plugin-v2
	forceMulticast bool
	networks       map[string]network
}

func New(client *docker.Client, weave *weaveapi.Client, name, scope string, dns, isPluginV2, forceMulticast bool) (skel.Driver, error) {
	driver := &driver{
		name:       name,
		scope:      scope,
		docker:     client,
		dns:        dns,
		isPluginV2: isPluginV2,
		// make sure that it's used only by plugin-v2
		forceMulticast: isPluginV2 && forceMulticast,
		networks:       make(map[string]network),
	}

	// Do not start watcher in the case of plugin v2, which prevents us from
	// configuring arp settings of containers.
	if client != nil {
		_, err := NewWatcher(client, weave, driver)
		if err != nil {
			return nil, err
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,9 +39,10 @@
 	// used only by plugin-v2
 	forceMulticast bool
 	networks       map[string]network
-}
-
-func New(client *docker.Client, weave *weaveapi.Client, name, scope string, dns, isPluginV2, forceMulticast bool) (skel.Driver, error) {
+	procPath       string
+}
+
+func New(client *docker.Client, weave *weaveapi.Client, name, scope string, dns, isPluginV2, forceMulticast bool, procPath string) (skel.Driver, error) {
 	driver := &driver{
 		name:       name,
 		scope:      scope,
@@ -51,6 +52,7 @@
 		// make sure that it's used only by plugin-v2
 		forceMulticast: isPluginV2 && forceMulticast,
 		networks:       make(map[string]network),
+		procPath:       procPath,
 	}
 
 	// Do not start watcher in the case of plugin v2, which prevents us from
@@ -134,7 +136,7 @@
 
 	// create veths. note we assume endpoint IDs are unique in the first 9 chars
 	name, peerName := vethPair(create.EndpointID)
-	if _, err := weavenet.CreateAndAttachVeth(name, peerName, weavenet.WeaveBridgeName, 0, false, true, nil); err != nil {
+	if _, err := weavenet.CreateAndAttachVeth(driver.procPath, name, peerName, weavenet.WeaveBridgeName, 0, false, true, nil); err != nil {
 		return nil, driver.error("JoinEndpoint", "%s", err)
 	}
 
```
