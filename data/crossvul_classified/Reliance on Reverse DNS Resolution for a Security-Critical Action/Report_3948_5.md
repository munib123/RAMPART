# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_5
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_5`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 15-55 of the vulnerable file.

	netplugin "github.com/weaveworks/weave/plugin/net"
	"github.com/weaveworks/weave/plugin/skel"
)

const (
	pluginV2Name    = "net-plugin"
	defaultNetwork  = "weave"
	MulticastOption = netplugin.MulticastOption
)

var Log = common.Log

type Config struct {
	Socket            string
	MeshSocket        string
	Enable            bool
	EnableV2          bool
	EnableV2Multicast bool
	DNS               bool
	DefaultSubnet     string
}

type Plugin struct {
	Config
}

func NewPlugin(config Config) *Plugin {
	if !config.Enable && !config.EnableV2 {
		return nil
	}
	plugin := &Plugin{Config: config}
	return plugin
}

func (plugin *Plugin) Start(weaveAPIAddr string, dockerClient *docker.Client, ready func()) {
	weave := weaveapi.NewClient(weaveAPIAddr, Log)

	Log.Info("Waiting for Weave API Server...")
	weave.WaitAPIServer(30)
	Log.Info("Finished waiting for Weave API Server")

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,7 @@
 	EnableV2Multicast bool
 	DNS               bool
 	DefaultSubnet     string
+	ProcPath          string // path to reach host /proc filesystem
 }
 
 type Plugin struct {
@@ -62,7 +63,7 @@
 	endChan := make(chan error, 1)
 
 	if plugin.Socket != "" {
-		globalListener, err := listenAndServe(dockerClient, weave, plugin.Socket, endChan, "global", false, plugin.DNS, plugin.EnableV2, plugin.EnableV2Multicast)
+		globalListener, err := listenAndServe(dockerClient, weave, plugin.Socket, endChan, "global", false, plugin.DNS, plugin.EnableV2, plugin.EnableV2Multicast, plugin.ProcPath)
 		if err != nil {
 			return err
 		}
@@ -70,7 +71,7 @@
 		defer globalListener.Close()
 	}
 	if plugin.MeshSocket != "" {
-		meshListener, err := listenAndServe(dockerClient, weave, plugin.MeshSocket, endChan, "local", true, plugin.DNS, plugin.EnableV2, plugin.EnableV2Multicast)
+		meshListener, err := listenAndServe(dockerClient, weave, plugin.MeshSocket, endChan, "local", true, plugin.DNS, plugin.EnableV2, plugin.EnableV2Multicast, plugin.ProcPath)
 		if err != nil {
 			return err
 		}
@@ -87,7 +88,7 @@
 	return <-endChan
 }
 
-func listenAndServe(dockerClient *docker.Client, weave *weaveapi.Client, address string, endChan chan<- error, scope string, withIpam, dns bool, isPluginV2, forceMulticast bool) (net.Listener, error) {
+func listenAndServe(dockerClient *docker.Client, weave *weaveapi.Client, address string, endChan chan<- error, scope string, withIpam, dns bool, isPluginV2, forceMulticast bool, procPath string) (net.Listener, error) {
 	var name string
 	if isPluginV2 {
 		name = pluginV2Name
@@ -95,7 +96,7 @@
 		name = pluginNameFromAddress(address)
 	}
 
-	d, err := netplugin.New(dockerClient, weave, name, scope, dns, isPluginV2, forceMulticast)
+	d, err := netplugin.New(dockerClient, weave, name, scope, dns, isPluginV2, forceMulticast, procPath)
 	if err != nil {
 		return nil, err
 	}
```
