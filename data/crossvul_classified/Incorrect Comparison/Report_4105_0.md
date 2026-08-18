# CrossVul Fix Pair: Incorrect Comparison in typescript
**Pair ID:** 4105_0
**Vulnerability Class:** Incorrect Comparison
**CWE:** CWE-697
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4105_0`)

## Vulnerability Information & PoC

## Description
Incorrect Comparison - This Pillar covers several possibilities: the comparison checks one factor incorrectly; the comparison should consider multiple factors, but it does not check at least one of those factors at all; ...

## Vulnerable Code
```typescript
Lines 193-235 of the vulnerable file.

        }

        // Check specified token type is being respected
        if (tokenTypeFilter && slpmsg.versionType !== tokenTypeFilter) {
            this.cachedValidations[txid].validity = null;
            this.cachedValidations[txid].waiting = false;
            this.cachedValidations[txid].invalidReason = "Validator was run with filter only considering token type: " + tokenTypeFilter + " as valid.";
            return false; // Don't save boolean result to cache incase cache is ever used with different token type.
        } else {
            if (this.cachedValidations[txid].validity !== false) {
                this.cachedValidations[txid].invalidReason = null;
            }
        }

        // Check DAG validity
        if (slpmsg.transactionType === SlpTransactionType.GENESIS) {
            // Check for NFT1 child (type 0x41)
            if (slpmsg.versionType === 0x41) {
                // An NFT1 parent should be provided at input index 0,
                // so we check this first before checking the whole parent DAG
                let input_txid = txn.inputs[0].prevTxId.toString("hex");
                let input_txhex = await this.retrieveRawTransaction(input_txid);
                let input_tx: Bitcore.Transaction = new Bitcore.Transaction(input_txhex);
                let input_slpmsg;
                try {
                    input_slpmsg = this.slp.parseSlpOutputScript(input_tx.outputs[0]._scriptBuffer);
                } catch (_) { }
                if (!input_slpmsg || input_slpmsg.versionType !== 0x81) {
                    this.cachedValidations[txid].validity = false;
                    this.cachedValidations[txid].waiting = false;
                    this.cachedValidations[txid].invalidReason = "NFT1 child GENESIS does not have a valid NFT1 parent input.";
                    return this.cachedValidations[txid].validity!;
                }
                // Check that the there is a burned output >0 in the parent txn SLP message
                if (input_slpmsg.transactionType === SlpTransactionType.SEND &&
                    (!input_slpmsg.sendOutputs![1].isGreaterThan(0)))
                {
                    this.cachedValidations[txid].validity = false;
                    this.cachedValidations[txid].waiting = false;
                    this.cachedValidations[txid].invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
                    return this.cachedValidations[txid].validity!;
                } else if ((input_slpmsg.transactionType === SlpTransactionType.GENESIS ||
                            input_slpmsg.transactionType === SlpTransactionType.MINT) &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -210,9 +210,10 @@
             if (slpmsg.versionType === 0x41) {
                 // An NFT1 parent should be provided at input index 0,
                 // so we check this first before checking the whole parent DAG
-                let input_txid = txn.inputs[0].prevTxId.toString("hex");
-                let input_txhex = await this.retrieveRawTransaction(input_txid);
-                let input_tx: Bitcore.Transaction = new Bitcore.Transaction(input_txhex);
+                const input_txid = txn.inputs[0].prevTxId.toString("hex");
+                const input_prevout = txn.inputs[0].outputIndex;
+                const input_txhex = await this.retrieveRawTransaction(input_txid);
+                const input_tx: Bitcore.Transaction = new Bitcore.Transaction(input_txhex);
                 let input_slpmsg;
                 try {
                     input_slpmsg = this.slp.parseSlpOutputScript(input_tx.outputs[0]._scriptBuffer);
@@ -224,21 +225,34 @@
                     return this.cachedValidations[txid].validity!;
                 }
                 // Check that the there is a burned output >0 in the parent txn SLP message
-                if (input_slpmsg.transactionType === SlpTransactionType.SEND &&
-                    (!input_slpmsg.sendOutputs![1].isGreaterThan(0)))
-                {
-                    this.cachedValidations[txid].validity = false;
-                    this.cachedValidations[txid].waiting = false;
-                    this.cachedValidations[txid].invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
-                    return this.cachedValidations[txid].validity!;
-                } else if ((input_slpmsg.transactionType === SlpTransactionType.GENESIS ||
-                            input_slpmsg.transactionType === SlpTransactionType.MINT) &&
-                            !input_slpmsg.genesisOrMintQuantity!.isGreaterThan(0))
-                {
-                    this.cachedValidations[txid].validity = false;
-                    this.cachedValidations[txid].waiting = false;
-                    this.cachedValidations[txid].invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
-                    return this.cachedValidations[txid].validity!;
+                if (input_slpmsg.transactionType === SlpTransactionType.SEND) {
+                    if (input_prevout > input_slpmsg.sendOutputs!.length - 1) {
+                        this.cachedValidations[txid].validity = false;
+                        this.cachedValidations[txid].waiting = false;
+                        this.cachedValidations[txid].invalidReason = "NFT1 child GENESIS does not have a valid NFT1 parent input.";
+                        return this.cachedValidations[txid].validity!;
+                    } else if (! input_slpmsg.sendOutputs![input_prevout].isGreaterThan(0)) {
+                        this.cachedValidations[txid].validity = false;
+                        this.cachedValidations[txid].waiting = false;
+                        this.cachedValidations[txid].invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
+                        return this.cachedValidations[txid].validity!;
+                    } else {
+                        this.cachedValidations[txid].validity = true;
+                        this.cachedValidations[txid].waiting = false;
+                    }
+                } else if (input_slpmsg.transactionType === SlpTransactionType.GENESIS ||
+                            input_slpmsg.transactionType === SlpTransactionType.MINT) {
+                    if (input_prevout !== 1) {
+                        this.cachedValidations[txid].validity = false;
+                        this.cachedValidations[txid].waiting = false;
+                        this.cachedValidations[txid].invalidReason = "NFT1 child GENESIS does not have a valid NFT1 parent input.";
+                        return this.cachedValidations[txid].validity!;
+                    } else if (!input_slpmsg.genesisOrMintQuantity!.isGreaterThan(0)) {
+                        this.cachedValidations[txid].validity = false;
+                        this.cachedValidations[txid].waiting = false;
+                        this.cachedValidations[txid].invalidReason = "NFT1 child's parent has SLP output that is not greater than zero.";
+                        return this.cachedValidations[txid].validity!;
+                    }
                 }
                 // Continue to check the NFT1 parent DAG
                 let nft_parent_dag_validity = await this.isValidSlpTxid(input_txid, undefined, 0x81);
```
