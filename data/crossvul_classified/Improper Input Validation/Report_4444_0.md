# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4444_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4444_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 1-28 of the vulnerable file.

package mqtt

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"text/template"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/brocaar/chirpstack-api/go/v3/gw"
	"github.com/brocaar/chirpstack-network-server/internal/backend/gateway"
	"github.com/brocaar/chirpstack-network-server/internal/backend/gateway/marshaler"
	"github.com/brocaar/chirpstack-network-server/internal/config"
	"github.com/brocaar/chirpstack-network-server/internal/helpers"
	"github.com/brocaar/chirpstack-network-server/internal/storage"
	"github.com/brocaar/lorawan"
)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,6 @@
 	"crypto/tls"
 	"crypto/x509"
 	"encoding/base64"
-	"encoding/hex"
 	"fmt"
 	"io/ioutil"
 	"strings"
@@ -248,20 +247,6 @@
 		"uplink_id":  uplinkID,
 		"gateway_id": gatewayID,
 	}).Info("gateway/mqtt: uplink frame received")
-
-	// Since with MQTT all subscribers will receive the uplink messages sent
-	// by all the gateways, the first instance receiving the message must lock it,
-	// so that other instances can ignore the same message (from the same gw).
-	key := fmt.Sprintf("lora:ns:uplink:lock:%s:%d:%d:%d:%s", gatewayID, uplinkFrame.TxInfo.Frequency, uplinkFrame.RxInfo.Board, uplinkFrame.RxInfo.Antenna, hex.EncodeToString(uplinkFrame.PhyPayload))
-	if locked, err := b.isLocked(key); err != nil || locked {
-		if err != nil {
-			log.WithError(err).WithFields(log.Fields{
-				"uplink_id": uplinkID,
-				"key":       key,
-			}).Error("gateway/mqtt: acquire lock error")
-		}
-		return
-	}
 
 	b.rxPacketChan <- uplinkFrame
 }
```
