# CrossVul Fix Pair: Out-of-bounds Write in go
**Pair ID:** 4585_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4585_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```go
Lines 1-30 of the vulnerable file.

package p2p

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/p2p/conn"
)

const (
	defaultDialTimeout      = time.Second
	defaultFilterTimeout    = 5 * time.Second
	defaultHandshakeTimeout = 3 * time.Second
)

// IPResolver is a behaviour subset of net.Resolver.
type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// accept is the container to carry the upgraded connection and NodeInfo from an
// asynchronously running routine to the Accept method.
type accept struct {
	netAddr  *NetAddress
	conn     net.Conn
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 	"time"
 
 	"github.com/pkg/errors"
+	"golang.org/x/net/netutil"
 
 	"github.com/tendermint/tendermint/crypto"
 	"github.com/tendermint/tendermint/p2p/conn"
@@ -122,11 +123,18 @@
 	return func(mt *MultiplexTransport) { mt.resolver = resolver }
 }
 
+// MultiplexTransportMaxIncomingConnections sets the maximum number of
+// simultaneous connections (incoming). Default: 0 (unlimited)
+func MultiplexTransportMaxIncomingConnections(n int) MultiplexTransportOption {
+	return func(mt *MultiplexTransport) { mt.maxIncomingConnections = n }
+}
+
 // MultiplexTransport accepts and dials tcp connections and upgrades them to
 // multiplexed peers.
 type MultiplexTransport struct {
-	netAddr  NetAddress
-	listener net.Listener
+	netAddr                NetAddress
+	listener               net.Listener
+	maxIncomingConnections int // see MaxIncomingConnections
 
 	acceptc chan accept
 	closec  chan struct{}
@@ -238,6 +246,10 @@
 	ln, err := net.Listen("tcp", addr.DialString())
 	if err != nil {
 		return err
+	}
+
+	if mt.maxIncomingConnections > 0 {
+		ln = netutil.LimitListener(ln, mt.maxIncomingConnections)
 	}
 
 	mt.netAddr = addr
```
