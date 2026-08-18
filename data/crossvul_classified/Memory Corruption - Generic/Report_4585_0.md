# CrossVul Fix Pair: Out-of-bounds Write in go
**Pair ID:** 4585_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4585_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```go
Lines 454-494 of the vulnerable file.

		peerFilters = append(
			peerFilters,
			// ABCI query for ID filtering.
			func(_ p2p.IPeerSet, p p2p.Peer) error {
				res, err := proxyApp.Query().QuerySync(abci.RequestQuery{
					Path: fmt.Sprintf("/p2p/filter/id/%s", p.ID()),
				})
				if err != nil {
					return err
				}
				if res.IsErr() {
					return fmt.Errorf("error querying abci app: %v", res)
				}

				return nil
			},
		)
	}

	p2p.MultiplexTransportConnFilters(connFilters...)(transport)
	return transport, peerFilters
}

func createSwitch(config *cfg.Config,
	transport p2p.Transport,
	p2pMetrics *p2p.Metrics,
	peerFilters []p2p.PeerFilterFunc,
	mempoolReactor *mempl.Reactor,
	bcReactor p2p.Reactor,
	consensusReactor *consensus.Reactor,
	evidenceReactor *evidence.Reactor,
	nodeInfo p2p.NodeInfo,
	nodeKey *p2p.NodeKey,
	p2pLogger log.Logger) *p2p.Switch {

	sw := p2p.NewSwitch(
		config.P2P,
		transport,
		p2p.WithMetrics(p2pMetrics),
		p2p.SwitchPeerFilters(peerFilters...),
	)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -471,6 +471,11 @@
 	}
 
 	p2p.MultiplexTransportConnFilters(connFilters...)(transport)
+
+	// Limit the number of incoming connections.
+	max := config.P2P.MaxNumInboundPeers + len(splitAndTrimEmpty(config.P2P.UnconditionalPeerIDs, ",", " "))
+	p2p.MultiplexTransportMaxIncomingConnections(max)(transport)
+
 	return transport, peerFilters
 }
 
```
