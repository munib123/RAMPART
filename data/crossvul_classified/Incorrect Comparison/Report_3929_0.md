# CrossVul Fix Pair: Incorrect Comparison in typescript
**Pair ID:** 3929_0
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3929_0`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```typescript
Lines 391-431 of the vulnerable file.

                    const inputSlpMsg = Slp.parseSlpOutputScript(inputTx.outputs[0].scriptPubKey);
                    if (inputSlpMsg.transactionType === SlpTransactionType.GENESIS) {
                        inputSlpMsg.tokenIdHex = inputTxid;
                    }
                    if (inputSlpMsg.tokenIdHex === slpmsg.tokenIdHex) {
                        if (inputSlpMsg.transactionType === SlpTransactionType.GENESIS ||
                            inputSlpMsg.transactionType === SlpTransactionType.MINT) {
                            if (txn.inputs[i].previousTxOutIndex === inputSlpMsg.batonVout) {
                                validation.parents.push({
                                    txid: txn.inputs[i].previousTxHash,
                                    vout: txn.inputs[i].previousTxOutIndex,
                                    versionType: inputSlpMsg.versionType,
                                    valid: null,
                                    inputQty: null,
                                });
                            }
                        }
                    }
                } catch (_) { }
            }
            if (validation.parents.length !== 1) {
                validation.validity = false;
                validation.waiting = false;
                validation.invalidReason = "MINT transaction must have 1 valid baton parent.";
                return validation.validity!;
            }
        } else if (slpmsg.transactionType === SlpTransactionType.SEND) {
            const tokenOutQty = slpmsg.sendOutputs!.reduce((t, v) => t.plus(v), new Big(0));
            let tokenInQty = new Big(0);
            for (let i = 0; i < txn.inputs.length; i++) {
                const inputTxid = txn.inputs[i].previousTxHash;
                const inputTxHex = await this.retrieveRawTransaction(inputTxid);
                const inputTx: Transaction = Transaction.parseFromBuffer(inputTxHex);
                try {
                    const inputSlpMsg = Slp.parseSlpOutputScript(inputTx.outputs[0].scriptPubKey);
                    if (inputSlpMsg.transactionType === SlpTransactionType.GENESIS) {
                        inputSlpMsg.tokenIdHex = inputTxid;
                    }
                    if (inputSlpMsg.tokenIdHex === slpmsg.tokenIdHex) {
                        if (inputSlpMsg.transactionType === SlpTransactionType.SEND) {
                            if (txn.inputs[i].previousTxOutIndex <= inputSlpMsg.sendOutputs!.length - 1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,10 +408,10 @@
                     }
                 } catch (_) { }
             }
-            if (validation.parents.length !== 1) {
+            if (validation.parents.length < 1) {
                 validation.validity = false;
                 validation.waiting = false;
-                validation.invalidReason = "MINT transaction must have 1 valid baton parent.";
+                validation.invalidReason = "MINT transaction must have at least 1 candidate baton parent input.";
                 return validation.validity!;
             }
         } else if (slpmsg.transactionType === SlpTransactionType.SEND) {
@@ -468,10 +468,14 @@
         // Set validity validation-cache for parents, and handle MINT condition with no valid input
         // we don't need to check proper token id since we only added parents with same ID in above steps.
         const parentTxids = [...new Set(validation.parents.map(p => p.txid))];
-        for (let i = 0; i < parentTxids.length; i++) {
-            const valid = await this.isValidSlpTxid({ txid: parentTxids[i] });
-            validation.parents.filter(p => p.txid === parentTxids[i]).map(p => p.valid = valid);
-            if (validation.details!.transactionType === SlpTransactionType.MINT && !valid) {
+        for (const id of parentTxids) {
+            const valid = await this.isValidSlpTxid({ txid: id });
+            validation.parents.filter(p => p.txid === id).map(p => p.valid = valid);
+        }
+
+        // Check MINT for exactly 1 valid MINT baton
+        if (validation.details!.transactionType === SlpTransactionType.MINT) {
+            if (validation.parents.filter(p => p.valid && p.inputQty === null).length !== 1) {
                 validation.validity = false;
                 validation.waiting = false;
                 validation.invalidReason = "MINT transaction with invalid baton parent.";
```
