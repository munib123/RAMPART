# CrossVul Fix Pair: Incorrect Comparison in typescript
**Pair ID:** 4106_0
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4106_0`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```typescript
Lines 329-371 of the vulnerable file.

        }

        // Check specified token type is being respected
        if (tokenTypeFilter && slpmsg.versionType !== tokenTypeFilter) {
            validation.validity = null;
            validation.waiting = false;
            validation.invalidReason = "Validator was run with filter only considering token type: " + tokenTypeFilter + " as valid.";
            return false; // Don't save boolean result to cache incase cache is ever used with different token type.
        } else {
            if (validation.validity !== false) {
                validation.invalidReason = null;
            }
        }

        // Check DAG validity
        if (slpmsg.transactionType === SlpTransactionType.GENESIS) {
            // Check for NFT1 child (type 0x41)
            if (slpmsg.versionType === 0x41) {
                // An NFT1 parent should be provided at input index 0,
                // so we check this first before checking the whole parent DAG
                const inputTxid = txn.inputs[0].previousTxHash;
                const inputTxHex = await this.retrieveRawTransaction(inputTxid);
                const inputTx: Transaction = Transaction.parseFromBuffer(inputTxHex);
                let inputSlpMsg;
                try {
                    inputSlpMsg = Slp.parseSlpOutputScript(inputTx.outputs[0].scriptPubKey);
                } catch (_) {}
                if (!inputSlpMsg || inputSlpMsg.versionType !== 0x81) {
                    validation.validity = false;
                    validation.waiting = false;
                    validation.invalidReason = "NFT1 child GENESIS does not have a valid NFT1 parent input.";
                    return validation.validity!;
                }
                // Check that the there is a burned output >0 in the parent txn SLP message
                if (inputSlpMsg.transactionType === SlpTransactionType.SEND &&
                    !inputSlpMsg.sendOutputs![1].gt(0)) {
                    validation.validity = false;
                    validation.waiting = false;
                    validation.invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
                    return validation.validity!;
                } else if ((inputSlpMsg.transactionType === SlpTransactionType.GENESIS ||
                            inputSlpMsg.transactionType === SlpTransactionType.MINT) &&
                            !inputSlpMsg.genesisOrMintQuantity!.gt(0)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -346,12 +346,13 @@
             if (slpmsg.versionType === 0x41) {
                 // An NFT1 parent should be provided at input index 0,
                 // so we check this first before checking the whole parent DAG
-                const inputTxid = txn.inputs[0].previousTxHash;
-                const inputTxHex = await this.retrieveRawTransaction(inputTxid);
-                const inputTx: Transaction = Transaction.parseFromBuffer(inputTxHex);
+                const inputPrevTxid = txn.inputs[0].previousTxHash;
+                const inputPrevOut = txn.inputs[0].previousTxOutIndex;
+                const inputPrevTxHex = await this.retrieveRawTransaction(inputPrevTxid);
+                const inputPrevTx: Transaction = Transaction.parseFromBuffer(inputPrevTxHex);
                 let inputSlpMsg;
                 try {
-                    inputSlpMsg = Slp.parseSlpOutputScript(inputTx.outputs[0].scriptPubKey);
+                    inputSlpMsg = Slp.parseSlpOutputScript(inputPrevTx.outputs[0].scriptPubKey);
                 } catch (_) {}
                 if (!inputSlpMsg || inputSlpMsg.versionType !== 0x81) {
                     validation.validity = false;
@@ -360,23 +361,38 @@
                     return validation.validity!;
                 }
                 // Check that the there is a burned output >0 in the parent txn SLP message
-                if (inputSlpMsg.transactionType === SlpTransactionType.SEND &&
-                    !inputSlpMsg.sendOutputs![1].gt(0)) {
-                    validation.validity = false;
-                    validation.waiting = false;
-                    validation.invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
-                    return validation.validity!;
-                } else if ((inputSlpMsg.transactionType === SlpTransactionType.GENESIS ||
-                            inputSlpMsg.transactionType === SlpTransactionType.MINT) &&
-                            !inputSlpMsg.genesisOrMintQuantity!.gt(0)) {
-                    validation.validity = false;
-                    validation.waiting = false;
-                    validation.invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
-                    return validation.validity!;
+                if (inputSlpMsg.transactionType === SlpTransactionType.SEND) {
+                    if (inputPrevOut > inputSlpMsg.sendOutputs!.length - 1) {
+                        validation.validity = false;
+                        validation.waiting = false;
+                        validation.invalidReason = "NFT1 child GENESIS does not have a valid NFT1 parent input.";
+                        return validation.validity!;
+                    }
+                    if (! inputSlpMsg.sendOutputs![inputPrevOut].gt(0)) {
+                        validation.validity = false;
+                        validation.waiting = false;
+                        validation.invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
+                        return validation.validity!;
+                    }
+                } else if (inputSlpMsg.transactionType === SlpTransactionType.GENESIS ||
+                            inputSlpMsg.transactionType === SlpTransactionType.MINT) {
+                    if (inputPrevOut !== 1) {
+                        validation.validity = false;
+                        validation.waiting = false;
+                        validation.invalidReason = "NFT1 child GENESIS does not have a valid NFT1 parent input.";
+                        return validation.validity!;
+                    }
+                    if (!inputSlpMsg.genesisOrMintQuantity!.gt(0)) {
+                        validation.validity = false;
+                        validation.waiting = false;
+                        validation.invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
+                        return validation.validity!;
+                    }
                 }
+
                 // Continue to check the NFT1 parent DAG
                 const nft_parent_dag_validity = await this.isValidSlpTxid({
-                    txid: inputTxid,
+                    txid: inputPrevTxid,
                     tokenIdFilter: undefined,
                     tokenTypeFilter: 0x81
                 });
```
