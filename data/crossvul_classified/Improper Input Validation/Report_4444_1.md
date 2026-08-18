# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4444_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4444_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 2-43 of the vulnerable file.


import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/brocaar/chirpstack-api/go/v3/gw"
	"github.com/brocaar/chirpstack-network-server/internal/band"
	"github.com/brocaar/chirpstack-network-server/internal/helpers"
	"github.com/brocaar/chirpstack-network-server/internal/models"
	"github.com/brocaar/chirpstack-network-server/internal/storage"
	"github.com/brocaar/lorawan"
)

// Templates used for generating Redis keys
const (
	CollectKeyTempl     = "lora:ns:rx:collect:%s"
	CollectLockKeyTempl = "lora:ns:rx:collect:%s:lock"
)

// collectAndCallOnce collects the package, sleeps the configured duraction and
// calls the callback only once with a slice of packets, sorted by signal
// strength (strongest at index 0). This method exists since multiple gateways
// are able to receive the same packet, but the packet needs to processed
// only once.
// It is safe to collect the same packet received by the same gateway twice.
// Since the underlying storage type is a set, the result will always be a
// unique set per gateway MAC and packet MIC.
func collectAndCallOnce(rxPacket gw.UplinkFrame, callback func(packet models.RXPacket) error) error {
	phyKey := hex.EncodeToString(rxPacket.PhyPayload)
	key := fmt.Sprintf(CollectKeyTempl, phyKey)
	lockKey := fmt.Sprintf(CollectLockKeyTempl, phyKey)

	// this way we can set a really low DeduplicationDelay for testing, without
	// the risk that the set already expired in redis on read
	deduplicationTTL := deduplicationDelay * 2
	if deduplicationTTL < time.Millisecond*200 {
		deduplicationTTL = time.Millisecond * 200
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,8 +19,8 @@
 
 // Templates used for generating Redis keys
 const (
-	CollectKeyTempl     = "lora:ns:rx:collect:%s"
-	CollectLockKeyTempl = "lora:ns:rx:collect:%s:lock"
+	CollectKeyTempl     = "lora:ns:rx:collect:%s:%s"
+	CollectLockKeyTempl = "lora:ns:rx:collect:%s:%s:lock"
 )
 
 // collectAndCallOnce collects the package, sleeps the configured duraction and
@@ -33,8 +33,14 @@
 // unique set per gateway MAC and packet MIC.
 func collectAndCallOnce(rxPacket gw.UplinkFrame, callback func(packet models.RXPacket) error) error {
 	phyKey := hex.EncodeToString(rxPacket.PhyPayload)
-	key := fmt.Sprintf(CollectKeyTempl, phyKey)
-	lockKey := fmt.Sprintf(CollectLockKeyTempl, phyKey)
+	txInfoB, err := proto.Marshal(rxPacket.TxInfo)
+	if err != nil {
+		return errors.Wrap(err, "marshal protobuf error")
+	}
+	txInfoHEX := hex.EncodeToString(txInfoB)
+
+	key := fmt.Sprintf(CollectKeyTempl, txInfoHEX, phyKey)
+	lockKey := fmt.Sprintf(CollectLockKeyTempl, txInfoHEX, phyKey)
 
 	// this way we can set a really low DeduplicationDelay for testing, without
 	// the risk that the set already expired in redis on read
```
