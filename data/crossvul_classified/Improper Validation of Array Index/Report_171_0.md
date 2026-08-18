# CrossVul Fix Pair: Improper Validation of Array Index in go
**Pair ID:** 171_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `171_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```go
Lines 2-42 of the vulnerable file.

// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package les implements the Light Ethereum Subprotocol.
package les

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/light"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discv5"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 
 import (
 	"encoding/binary"
+	"encoding/json"
 	"errors"
 	"fmt"
 	"math/big"
@@ -441,7 +442,7 @@
 
 			// Advance to the next header of the query
 			switch {
-			case query.Origin.Hash != (common.Hash{}) && query.Reverse:
+			case hashMode && query.Reverse:
 				// Hash based traversal towards the genesis block
 				for i := 0; i < int(query.Skip)+1; i++ {
 					if header := pm.blockchain.GetHeader(query.Origin.Hash, number); header != nil {
@@ -452,16 +453,26 @@
 						break
 					}
 				}
-			case query.Origin.Hash != (common.Hash{}) && !query.Reverse:
+			case hashMode && !query.Reverse:
 				// Hash based traversal towards the leaf block
-				if header := pm.blockchain.GetHeaderByNumber(origin.Number.Uint64() + query.Skip + 1); header != nil {
-					if pm.blockchain.GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
-						query.Origin.Hash = header.Hash()
+				var (
+					current = origin.Number.Uint64()
+					next    = current + query.Skip + 1
+				)
+				if next <= current {
+					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
+					p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
+					unknown = true
+				} else {
+					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
+						if pm.blockchain.GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
+							query.Origin.Hash = header.Hash()
+						} else {
+							unknown = true
+						}
 					} else {
 						unknown = true
 					}
-				} else {
-					unknown = true
 				}
 			case query.Reverse:
 				// Number based traversal towards the genesis block
```
