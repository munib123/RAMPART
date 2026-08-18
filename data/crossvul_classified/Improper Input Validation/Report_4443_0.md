# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4443_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4443_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 8-50 of the vulnerable file.

	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/brocaar/chirpstack-api/go/v3/common"
	"github.com/brocaar/chirpstack-api/go/v3/gw"
	"github.com/brocaar/chirpstack-network-server/internal/helpers"
	"github.com/brocaar/chirpstack-network-server/internal/logging"
	"github.com/brocaar/chirpstack-network-server/internal/storage"
	"github.com/brocaar/lorawan"
)

// UpdateMetaDataInRxInfoSet updates the gateway meta-data in the
// given rx-info set. It will:
//   - add the gateway location
//   - set the FPGA id if available
//   - decrypt the fine-timestamp (if available and AES key is set)
func UpdateMetaDataInRxInfoSet(ctx context.Context, db sqlx.Queryer, rxInfo []*gw.UplinkRXInfo) error {
	for i := range rxInfo {
		id := helpers.GetGatewayID(rxInfo[i])
		g, err := storage.GetAndCacheGateway(ctx, db, id)
		if err != nil {
			log.WithFields(log.Fields{
				"ctx_id":     ctx.Value(logging.ContextIDKey),
				"gateway_id": id,
			}).WithError(err).Error("get gateway error")
			continue
		}

		// set gateway location
		rxInfo[i].Location = &common.Location{
			Latitude:  g.Location.Latitude,
			Longitude: g.Location.Longitude,
			Altitude:  g.Altitude,
		}

		var board storage.GatewayBoard
		if int(rxInfo[i].Board) < len(g.Boards) {
			board = g.Boards[int(rxInfo[i].Board)]
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,68 +25,53 @@
 //   - add the gateway location
 //   - set the FPGA id if available
 //   - decrypt the fine-timestamp (if available and AES key is set)
-func UpdateMetaDataInRxInfoSet(ctx context.Context, db sqlx.Queryer, rxInfo []*gw.UplinkRXInfo) error {
-	for i := range rxInfo {
-		id := helpers.GetGatewayID(rxInfo[i])
+func UpdateMetaDataInRxInfoSet(ctx context.Context, db sqlx.Queryer, rxInfoSet []*gw.UplinkRXInfo) []*gw.UplinkRXInfo {
+	var out []*gw.UplinkRXInfo
+
+	for i := range rxInfoSet {
+		rxInfo := rxInfoSet[i]
+
+		id := helpers.GetGatewayID(rxInfo)
 		g, err := storage.GetAndCacheGateway(ctx, db, id)
 		if err != nil {
-			log.WithFields(log.Fields{
-				"ctx_id":     ctx.Value(logging.ContextIDKey),
-				"gateway_id": id,
-			}).WithError(err).Error("get gateway error")
+			if errors.Cause(err) == storage.ErrDoesNotExist {
+				log.WithFields(log.Fields{
+					"ctx_id":     ctx.Value(logging.ContextIDKey),
+					"gateway_id": id,
+				}).Warning("uplink received by unknown gateway")
+			} else {
+				log.WithFields(log.Fields{
+					"ctx_id":     ctx.Value(logging.ContextIDKey),
+					"gateway_id": id,
+				}).WithError(err).Error("get gateway error")
+			}
 			continue
 		}
 
 		// set gateway location
-		rxInfo[i].Location = &common.Location{
+		rxInfo.Location = &common.Location{
 			Latitude:  g.Location.Latitude,
 			Longitude: g.Location.Longitude,
 			Altitude:  g.Altitude,
 		}
 
 		var board storage.GatewayBoard
-		if int(rxInfo[i].Board) < len(g.Boards) {
-			board = g.Boards[int(rxInfo[i].Board)]
+		if int(rxInfo.Board) < len(g.Boards) {
+			board = g.Boards[int(rxInfo.Board)]
 		}
 
 		// set FPGA ID
 		// this is useful when the AES decryption key is not set as it
 		// indicates which key to use for decryption
-		if rxInfo[i].FineTimestampType == gw.FineTimestampType_ENCRYPTED && board.FPGAID != nil {
-			tsInfo := rxInfo[i].GetEncryptedFineTimestamp()
-			if tsInfo == nil {
-				log.WithFields(log.Fields{
-					"ctx_id":     ctx.Value(logging.ContextIDKey),
-					"gateway_id": id,
-				}).Error("encrypted_fine_timestamp must not be nil")
-				continue
-			}
-
+		if tsInfo := rxInfo.GetEncryptedFineTimestamp(); tsInfo != nil && board.FPGAID != nil {
 			if len(tsInfo.FpgaId) == 0 {
 				tsInfo.FpgaId = board.FPGAID[:]
 			}
 		}
 
 		// decrypt fine-timestamp when the AES key is known
-		if rxInfo[i].FineTimestampType == gw.FineTimestampType_ENCRYPTED && board.FineTimestampKey != nil {
-			tsInfo := rxInfo[i].GetEncryptedFineTimestamp()
-			if tsInfo == nil {
-				log.WithFields(log.Fields{
-					"ctx_id":     ctx.Value(logging.ContextIDKey),
-					"gateway_id": id,
-				}).Error("encrypted_fine_timestamp must not be nil")
-				continue
-			}
-
-			if rxInfo[i].Time == nil {
-				log.WithFields(log.Fields{
-					"ctx_id":     ctx.Value(logging.ContextIDKey),
-					"gateway_id": id,
-				}).Error("time must not be nil")
-				continue
-			}
-
-			rxTime, err := ptypes.Timestamp(rxInfo[i].Time)
+		if tsInfo := rxInfo.GetEncryptedFineTimestamp(); tsInfo != nil && board.FineTimestampKey != nil {
+			rxTime, err := ptypes.Timestamp(rxInfo.GetTime())
 			if err != nil {
 				log.WithFields(log.Fields{
 					"ctx_id":     ctx.Value(logging.ContextIDKey),
@@ -103,14 +88,16 @@
 				continue
 			}
 
-			rxInfo[i].FineTimestampType = gw.FineTimestampType_PLAIN
-			rxInfo[i].FineTimestamp = &gw.UplinkRXInfo_PlainFineTimestamp{
+			rxInfo.FineTimestampType = gw.FineTimestampType_PLAIN
+			rxInfo.FineTimestamp = &gw.UplinkRXInfo_PlainFineTimestamp{
 				PlainFineTimestamp: &plainTS,
 			}
 		}
+
+		out = append(out, rxInfo)
 	}
 
-	return nil
+	return out
 }
 
 func decryptFineTimestamp(key lorawan.AES128Key, rxTime time.Time, ts gw.EncryptedFineTimestamp) (gw.PlainFineTimestamp, error) {
```
