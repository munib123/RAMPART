# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4443_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4443_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 161-201 of the vulnerable file.

		if err != nil {
			cause := errors.Cause(err)
			if cause == storage.ErrDoesNotExist || cause == storage.ErrFrameCounterReset || cause == storage.ErrInvalidMIC || cause == storage.ErrFrameCounterRetransmission {
				if _, err := controller.Client().HandleRejectedUplinkFrameSet(ctx, &nc.HandleRejectedUplinkFrameSetRequest{
					FrameSet: &gw.UplinkFrameSet{
						PhyPayload: uplinkFrame.PhyPayload,
						TxInfo:     rxPacket.TXInfo,
						RxInfo:     rxPacket.RXInfoSet,
					},
				}); err != nil {
					log.WithError(err).Error("uplink: call controller HandleRejectedUplinkFrameSet RPC error")
				}
			}
		}

		return err
	})
}

func handleCollectedUplink(ctx context.Context, uplinkFrame gw.UplinkFrame, rxPacket models.RXPacket) error {
	var uplinkIDs []uuid.UUID
	for _, p := range rxPacket.RXInfoSet {
		uplinkIDs = append(uplinkIDs, helpers.GetUplinkID(p))
	}

	log.WithFields(log.Fields{
		"uplink_ids": uplinkIDs,
		"mtype":      rxPacket.PHYPayload.MHDR.MType,
		"ctx_id":     ctx.Value(logging.ContextIDKey),
	}).Info("uplink: frame(s) collected")

	// update the gateway meta-data
	if err := gateway.UpdateMetaDataInRxInfoSet(ctx, storage.DB(), rxPacket.RXInfoSet); err != nil {
		log.WithError(err).Error("uplink: update gateway meta-data in rx-info set error")
	}

	// log the frame for each receiving gateway.
	if err := framelog.LogUplinkFrameForGateways(ctx, ns.UplinkFrameLog{
		PhyPayload: uplinkFrame.PhyPayload,
		TxInfo:     rxPacket.TXInfo,
		RxInfo:     rxPacket.RXInfoSet,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -178,6 +178,14 @@
 }
 
 func handleCollectedUplink(ctx context.Context, uplinkFrame gw.UplinkFrame, rxPacket models.RXPacket) error {
+	// update the gateway meta-data
+	rxPacket.RXInfoSet = gateway.UpdateMetaDataInRxInfoSet(ctx, storage.DB(), rxPacket.RXInfoSet)
+
+	// Return if the RXInfoSet is empty.
+	if len(rxPacket.RXInfoSet) == 0 {
+		return nil
+	}
+
 	var uplinkIDs []uuid.UUID
 	for _, p := range rxPacket.RXInfoSet {
 		uplinkIDs = append(uplinkIDs, helpers.GetUplinkID(p))
@@ -188,11 +196,6 @@
 		"mtype":      rxPacket.PHYPayload.MHDR.MType,
 		"ctx_id":     ctx.Value(logging.ContextIDKey),
 	}).Info("uplink: frame(s) collected")
-
-	// update the gateway meta-data
-	if err := gateway.UpdateMetaDataInRxInfoSet(ctx, storage.DB(), rxPacket.RXInfoSet); err != nil {
-		log.WithError(err).Error("uplink: update gateway meta-data in rx-info set error")
-	}
 
 	// log the frame for each receiving gateway.
 	if err := framelog.LogUplinkFrameForGateways(ctx, ns.UplinkFrameLog{
```
