# CrossVul Fix Pair: Incorrect Comparison in typescript
**Pair ID:** 3928_0
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3928_0`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```typescript
Lines 265-305 of the vulnerable file.

                try {
                    let input_slpmsg = this.slp.parseSlpOutputScript(input_tx.outputs[0]._scriptBuffer);
                    if (input_slpmsg.transactionType === SlpTransactionType.GENESIS) {
                        input_slpmsg.tokenIdHex = input_txid;
                    }
                    if (input_slpmsg.tokenIdHex === slpmsg.tokenIdHex) {
                        if (input_slpmsg.transactionType === SlpTransactionType.GENESIS || input_slpmsg.transactionType === SlpTransactionType.MINT) {
                            if (txn.inputs[i].outputIndex === input_slpmsg.batonVout) {
                                this.cachedValidations[txid].parents.push({
                                    txid: txn.inputs[i].prevTxId.toString("hex"),
                                    vout: txn.inputs[i].outputIndex!,
                                    versionType: input_slpmsg.versionType,
                                    valid: null,
                                    inputQty: null,
                                });
                            }
                        }
                    }
                } catch (_) {}
            }
            if (this.cachedValidations[txid].parents.length !== 1) {
                this.cachedValidations[txid].validity = false;
                this.cachedValidations[txid].waiting = false;
                this.cachedValidations[txid].invalidReason = "MINT transaction must have 1 valid baton parent.";
                return this.cachedValidations[txid].validity!;
            }
        }
        else if (slpmsg.transactionType === SlpTransactionType.SEND) {
            const tokenOutQty = slpmsg.sendOutputs!.reduce((t, v) => { return t.plus(v); }, new BigNumber(0));
            let tokenInQty = new BigNumber(0);
            for (let i = 0; i < txn.inputs.length; i++) {
                let input_txid = txn.inputs[i].prevTxId.toString("hex");
                let input_txhex = await this.retrieveRawTransaction(input_txid);
                let input_tx: Bitcore.Transaction = new Bitcore.Transaction(input_txhex);
                try {
                    let input_slpmsg = this.slp.parseSlpOutputScript(input_tx.outputs[0]._scriptBuffer);
                    if (input_slpmsg.transactionType === SlpTransactionType.GENESIS) {
                        input_slpmsg.tokenIdHex = input_txid;
                    }
                    if (input_slpmsg.tokenIdHex === slpmsg.tokenIdHex) {
                        if (input_slpmsg.transactionType === SlpTransactionType.SEND) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -282,10 +282,10 @@
                     }
                 } catch (_) {}
             }
-            if (this.cachedValidations[txid].parents.length !== 1) {
-                this.cachedValidations[txid].validity = false;
-                this.cachedValidations[txid].waiting = false;
-                this.cachedValidations[txid].invalidReason = "MINT transaction must have 1 valid baton parent.";
+            if (this.cachedValidations[txid].parents.length < 1) {
+                this.cachedValidations[txid].validity = false;
+                this.cachedValidations[txid].waiting = false;
+                this.cachedValidations[txid].invalidReason = "MINT transaction must have at least 1 candidate baton parent input.";
                 return this.cachedValidations[txid].validity!;
             }
         }
@@ -342,10 +342,14 @@
         // Set validity validation-cache for parents, and handle MINT condition with no valid input
         // we don't need to check proper token id since we only added parents with same ID in above steps.
         const parentTxids = [...new Set(this.cachedValidations[txid].parents.map(p => p.txid))];
-        for (let i = 0; i < parentTxids.length; i++) {
-            const valid = await this.isValidSlpTxid(parentTxids[i]);
-            this.cachedValidations[txid].parents.filter(p => p.txid === parentTxids[i]).map(p => p.valid = valid);
-            if (this.cachedValidations[txid].details!.transactionType === SlpTransactionType.MINT && !valid) {
+        for (const id of parentTxids) {
+            const valid = await this.isValidSlpTxid(id);
+            this.cachedValidations[txid].parents.filter(p => p.txid === id).map(p => p.valid = valid);
+        }
+
+        // Check MINT for exactly 1 valid MINT baton
+        if (this.cachedValidations[txid].details!.transactionType === SlpTransactionType.MINT) {
+            if (this.cachedValidations[txid].parents.filter(p => p.valid && p.inputQty === null).length !== 1) {
                 this.cachedValidations[txid].validity = false;
                 this.cachedValidations[txid].waiting = false;
                 this.cachedValidations[txid].invalidReason = "MINT transaction with invalid baton parent.";
```
