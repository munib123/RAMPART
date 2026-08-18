# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 1106_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1106_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-23 of the vulnerable file.

import { SlpAddressUtxoResult, SlpTransactionDetails, SlpTransactionType, SlpUtxoJudgement, SlpBalancesResult, utxo, SlpVersionType, logger, Primatives } from '../index';
import { SlpTokenType1 } from './slptokentype1';
import { Utils } from './utils';

import { BITBOX } from 'bitbox-sdk';
import * as bchaddr from 'bchaddrjs-slp';
import BigNumber from 'bignumber.js';

export interface SlpPaymentRequest {
    address: string,
    amountBch?: number, 
    amountToken?: number,
    tokenId?: string,
    tokenFlags?: string[]
}

export interface PushDataOperation {
    opcode: number, 
    data: Buffer|null
}

export interface configBuildNFT1GenesisOpReturn {
    ticker: string|null;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,22 +1,24 @@
-import { SlpAddressUtxoResult, SlpTransactionDetails, SlpTransactionType, SlpUtxoJudgement, SlpBalancesResult, utxo, SlpVersionType, logger, Primatives } from '../index';
-import { SlpTokenType1 } from './slptokentype1';
-import { Utils } from './utils';
-
-import { BITBOX } from 'bitbox-sdk';
-import * as bchaddr from 'bchaddrjs-slp';
-import BigNumber from 'bignumber.js';
+import {
+    logger, Primatives, SlpAddressUtxoResult, SlpBalancesResult,
+    SlpTransactionDetails, SlpTransactionType, SlpUtxoJudgement, SlpVersionType, utxo } from "../index";
+import { SlpTokenType1 } from "./slptokentype1";
+import { Utils } from "./utils";
+
+import * as bchaddr from "bchaddrjs-slp";
+import BigNumber from "bignumber.js";
+import { BITBOX } from "bitbox-sdk";
 
 export interface SlpPaymentRequest {
-    address: string,
-    amountBch?: number, 
-    amountToken?: number,
-    tokenId?: string,
-    tokenFlags?: string[]
+    address: string;
+    amountBch?: number;
+    amountToken?: number;
+    tokenId?: string;
+    tokenFlags?: string[];
 }
 
 export interface PushDataOperation {
-    opcode: number, 
-    data: Buffer|null
+    opcode: number;
+    data: Buffer|null;
 }
 
 export interface configBuildNFT1GenesisOpReturn {
@@ -30,10 +32,10 @@
     ticker: string|null;
     name: string|null;
     documentUri: string|null;
-    hash: Buffer|null,
+    hash: Buffer|null;
     decimals: number;
     batonVout: number|null; // normally this is null (for fixed supply) or 2+ for flexible
-    initialQuantity: BigNumber
+    initialQuantity: BigNumber;
 }
 
 export interface configBuildMintOpReturn {
@@ -43,24 +45,24 @@
 }
 
 export interface configBuildSendOpReturn {
-    tokenIdHex: string; 
-    outputQtyArray: BigNumber[]
+    tokenIdHex: string;
+    outputQtyArray: BigNumber[];
 }
 
 export interface configBuildRawNFT1GenesisTx {
-    slpNFT1GenesisOpReturn: Buffer; 
+    slpNFT1GenesisOpReturn: Buffer;
     mintReceiverAddress: string;
     mintReceiverSatoshis?: BigNumber;
-    //batonReceiverAddress: string|null;
-    //batonReceiverSatoshis?: BigNumber;
+    // batonReceiverAddress: string|null;
+    // batonReceiverSatoshis?: BigNumber;
     bchChangeReceiverAddress: string;
     input_utxos: utxo[];
     parentTokenIdHex: string;
-    //allowed_token_burning: string[]|null;
+    // allowed_token_burning: string[]|null;
 }
 
 export interface configBuildRawGenesisTx {
-    slpGenesisOpReturn: Buffer; 
+    slpGenesisOpReturn: Buffer;
     mintReceiverAddress: string;
     mintReceiverSatoshis?: BigNumber;
     batonReceiverAddress: string|null;
@@ -75,7 +77,7 @@
     input_token_utxos: utxo[];
     tokenReceiverAddressArray: string[];
     bchChangeReceiverAddress: string;
-    requiredNonTokenOutputs?: { satoshis: number, receiverAddress: string }[]
+    requiredNonTokenOutputs?: Array<{ satoshis: number, receiverAddress: string }>;
     extraFee?: number;
 }
 
@@ -104,8 +106,9 @@
 }
 
 export interface SlpValidator {
-    isValidSlpTxid(txid: string, tokenIdFilter?: string|null, tokenTypeFilter?: number|null, logger?: logger): Promise<boolean>;
     getRawTransactions: (txid: string[]) => Promise<string[]>;
+    isValidSlpTxid(txid: string, tokenIdFilter?: string|null,
+                   tokenTypeFilter?: number|null, logger?: logger): Promise<boolean>;
     validateSlpTransactions(txids: string[]): Promise<string[]>;
 }
 
@@ -114,21 +117,15 @@
 }
 
 export class Slp {
-    BITBOX: BITBOX;
-    constructor(bitbox: BITBOX) {
-        if(!bitbox)
-            throw Error("Must provide BITBOX instance to class constructor.")
-        this.BITBOX = bitbox;
-    }
-
-    get lokadIdHex() { return "534c5000" }
-
-    static buildGenesisOpReturn(config: configBuildGenesisOpReturn, type = 0x01) {
+
+    get lokadIdHex() { return "534c5000"; }
+
+    public static buildGenesisOpReturn(config: configBuildGenesisOpReturn, type = 0x01) {
         let hash;
-        try { 
-            hash = config.hash!.toString('hex')
-        } catch (_) { hash = null }
-        
+        try {
+            hash = config.hash!.toString("hex");
+        } catch (_) { hash = null; }
+
         return SlpTokenType1.buildGenesisOpReturn(
             config.ticker,
             config.name,
@@ -136,106 +133,171 @@
             hash,
             config.decimals,
             config.batonVout,
-            config.initialQuantity, 
-            type
-        )
-    }
-
-    static buildMintOpReturn(config: configBuildMintOpReturn, type = 0x01) {
+            config.initialQuantity,
+            type,
+        );
+    }
+
+    public static buildMintOpReturn(config: configBuildMintOpReturn, type = 0x01) {
         return SlpTokenType1.buildMintOpReturn(
             config.tokenIdHex,
             config.batonVout,
-            config.mintQuantity, 
-            type
-        )
-    }
-
-    static buildSendOpReturn(config: configBuildSendOpReturn, type = 0x01) {
+            config.mintQuantity,
+            type,
+        );
+    }
+
+    public static buildSendOpReturn(config: configBuildSendOpReturn, type = 0x01) {
         return SlpTokenType1.buildSendOpReturn(
             config.tokenIdHex,
             config.outputQtyArray,
-            type
-        )
-    }
-
-    buildRawNFT1GenesisTx(config: configBuildRawNFT1GenesisTx, type = 0x01) {
-        let config2: configBuildRawGenesisTx = {
+            type,
+        );
+    }
+
+    public static parseChunkToInt(intBytes: Buffer, minByteLen: number, maxByteLen: number, raise_on_Null = false) {
+        // # Parse data as unsigned-big-endian encoded integer.
+        // # For empty data different possibilities may occur:
+        // #      minByteLen <= 0 : return 0
+        // #      raise_on_Null == False and minByteLen > 0: return None
+        // #      raise_on_Null == True and minByteLen > 0:  raise SlpInvalidOutputMessage
+        if (intBytes.length >= minByteLen && intBytes.length <= maxByteLen) {
+            return intBytes.readUIntBE(0, intBytes.length)
+        }
+        if (intBytes.length === 0 && !raise_on_Null) {
+            return null;
+        }
+        throw Error("Field has wrong length");
+    }
+
+    public static preSendSlpJudgementCheck(txo: SlpAddressUtxoResult, tokenId: string) {
+        if (txo.slpUtxoJudgement === undefined ||
+            txo.slpUtxoJudgement === null ||
+            txo.slpUtxoJudgement === SlpUtxoJudgement.UNKNOWN) {
+            throw Error("There at least one input UTXO that does not have a proper SLP judgement");
+        }
+        if (txo.slpUtxoJudgement === SlpUtxoJudgement.UNSUPPORTED_TYPE) {
+            throw Error("There is at least one input UTXO that is an Unsupported SLP type.");
+        }
+        if (txo.slpUtxoJudgement === SlpUtxoJudgement.SLP_BATON) {
+            throw Error("There is at least one input UTXO that is a baton.  \
+                        You can only spend batons in a MINT transaction.");
+        }
+        if (txo.slpTransactionDetails) {
+            if (txo.slpUtxoJudgement === SlpUtxoJudgement.SLP_TOKEN) {
+                if (!txo.slpUtxoJudgementAmount) {
+                    throw Error("There is at least one input token that does not \
+                                have the 'slpUtxoJudgementAmount' property set.");
+                }
+                if (txo.slpTransactionDetails.tokenIdHex !== tokenId) {
+                    throw Error("There is at least one input UTXO that \
+                                is a different SLP token than the one specified.");
+                }
+                return txo.slpTransactionDetails.tokenIdHex === tokenId;
+            }
+        }
+        return false;
+    }
+    public BITBOX: BITBOX;
+    constructor(bitbox: BITBOX) {
+        if (!bitbox) {
+            throw Error("Must provide BITBOX instance to class constructor.")
+        }
+        this.BITBOX = bitbox;
+    }
+
... (diff truncated)
```
