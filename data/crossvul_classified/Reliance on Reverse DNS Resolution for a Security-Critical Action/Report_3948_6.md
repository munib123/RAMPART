# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_6
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_6`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 436-476 of the vulnerable file.

	if !noDNS {
		ns, dnsserver = createDNSServer(dnsConfig, router.Router, isKnownPeer)
		observeContainers(ns)
		ns.Start()
		defer ns.Stop()
		dnsserver.ActivateAndServe()
		if dockerCli != nil {
			populateDNS(ns, dockerCli, name, bridgeConfig.WeaveBridgeName)
		}
		defer dnsserver.Stop()
	}

	router.Start()
	if errors := router.InitiateConnections(peers, false); len(errors) > 0 {
		Log.Fatal(common.ErrorMessages(errors))
	}
	checkFatal(router.CreateRestartSentinel())

	pluginConfig.DNS = !noDNS
	pluginConfig.DefaultSubnet = defaultSubnet.String()
	plugin := plugin.NewPlugin(pluginConfig)

	// The weave script always waits for a status call to succeed,
	// so there is no point in doing "weave launch --http-addr ''".
	// This is here to support stand-alone use of weaver.
	if httpAddr != "" {
		muxRouter := mux.NewRouter()
		if allocator != nil {
			allocator.HandleHTTP(muxRouter, defaultSubnet, dockerCli)
		}
		if ns != nil {
			ns.HandleHTTP(muxRouter, dockerCli)
		}
		router.HandleHTTP(muxRouter)
		HandleHTTP(muxRouter, version, router, allocator, defaultSubnet, ns, dnsserver, proxy, plugin, &waitReady)
		HandleHTTPPeer(muxRouter, allocator, discoveryEndpoint, token, name.String())
		muxRouter.Methods("GET").Path("/metrics").Handler(metricsHandler(router, allocator, ns, dnsserver))
		if proxy != nil {
			muxRouter.Methods("GET").Path("/proxyaddrs").HandlerFunc(proxy.StatusHTTP)
		}
		http.Handle("/", common.LoggingHTTPHandler(muxRouter))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -453,6 +453,7 @@
 
 	pluginConfig.DNS = !noDNS
 	pluginConfig.DefaultSubnet = defaultSubnet.String()
+	pluginConfig.ProcPath = procPath
 	plugin := plugin.NewPlugin(pluginConfig)
 
 	// The weave script always waits for a status call to succeed,
```
