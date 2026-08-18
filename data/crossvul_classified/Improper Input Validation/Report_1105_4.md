# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 1105_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1105_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import { Script } from './script';

import Big from 'big.js';

export enum SlpTransactionType {
    "GENESIS" = "GENESIS", 
    "MINT" = "MINT", 
    "SEND" = "SEND"
}

export enum SlpVersionType {
    "TokenVersionType1" = 1,
    "TokenVersionType1_NFT_Child" = 65,
    "TokenVersionType1_NFT_Parent" = 129
}

export interface SlpTransactionDetails {
    transactionType: SlpTransactionType;
    tokenIdHex: string;
    versionType: SlpVersionType;
    timestamp?: string;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,17 +1,17 @@
-import { Script } from './script';
-
-import Big from 'big.js';
+import { Script } from "./script";
+
+import Big from "big.js";
 
 export enum SlpTransactionType {
-    "GENESIS" = "GENESIS", 
-    "MINT" = "MINT", 
-    "SEND" = "SEND"
+    "GENESIS" = "GENESIS",
+    "MINT" = "MINT",
+    "SEND" = "SEND",
 }
 
 export enum SlpVersionType {
     "TokenVersionType1" = 1,
     "TokenVersionType1_NFT_Child" = 65,
-    "TokenVersionType1_NFT_Parent" = 129
+    "TokenVersionType1_NFT_Parent" = 129,
 }
 
 export interface SlpTransactionDetails {
@@ -21,7 +21,7 @@
     timestamp?: string;
     symbol: string;
     name: string;
-    documentUri: string|Buffer; 
+    documentUri: string|Buffer;
     documentSha256: Buffer|null;
     decimals: number;
     containsBaton: boolean;
@@ -31,142 +31,153 @@
 }
 
 export interface PushDataOperation {
-    opcode: number, 
-    data: Buffer|null
+    opcode: number;
+    data: Buffer|null;
 }
 
 export class Slp {
 
-    static get lokadIdHex() { return "534c5000" }
+    static get lokadIdHex() { return "534c5000"; }
 
     // get list of data chunks resulting from data push operations
-    static parseOpReturnToChunks(script: Buffer, allow_op_0=false, allow_op_number=false) {
+    public static parseOpReturnToChunks(script: Buffer, allowOP_0= false, allowOP_number= false) {
         // """Extract pushed bytes after opreturn. Returns list of bytes() objects,
         // one per push.
         let ops: PushDataOperation[];
-    
+
         // Strict refusal of non-push opcodes; bad scripts throw OpreturnError."""
         try {
             ops = this.getScriptOperations(script);
-        } catch(e) {
-            //console.log(e);
-            throw Error('Script error');
-        }
-
-        if(ops[0].opcode !== Script.opcodes.OP_RETURN)
-            throw Error('No OP_RETURN');
-        let chunks: (Buffer|null)[] = [];
+        } catch (e) {
+            // console.log(e);
+            throw Error("Script error");
+        }
+
+        if (ops[0].opcode !== Script.opcodes.OP_RETURN) {
+            throw Error("No OP_RETURN");
+        }
+        const chunks: Array<Buffer|null> = [];
         ops.slice(1).forEach(opitem => {
-            if(opitem.opcode > Script.opcodes.OP_16)
+            if (opitem.opcode > Script.opcodes.OP_16) {
                 throw Error("Non-push opcode");
-            if(opitem.opcode > Script.opcodes.OP_PUSHDATA4) {
-                if(opitem.opcode === 80)
-                    throw Error('Non-push opcode');
-                if(!allow_op_number)
-                    throw Error('OP_1NEGATE to OP_16 not allowed');
-                if(opitem.opcode === Script.opcodes.OP_1NEGATE)
+            }
+            if (opitem.opcode > Script.opcodes.OP_PUSHDATA4) {
+                if (opitem.opcode === 80) {
+                    throw Error("Non-push opcode");
+                }
+                if (!allowOP_number) {
+                    throw Error("OP_1NEGATE to OP_16 not allowed");
+                }
+                if (opitem.opcode === Script.opcodes.OP_1NEGATE) {
                     opitem.data = Buffer.from([0x81]);
-                else // OP_1 - OP_16
+                } else { // OP_1 - OP_16
                     opitem.data = Buffer.from([opitem.opcode - 80]);
-            }
-            if(opitem.opcode === Script.opcodes.OP_0 && !allow_op_0){
-                throw Error('OP_0 not allowed');
-            }
-            chunks.push(opitem.data)
+                }
+            }
+            if (opitem.opcode === Script.opcodes.OP_0 && !allowOP_0) {
+                throw Error("OP_0 not allowed");
+            }
+            chunks.push(opitem.data);
         });
-        //console.log(chunks);
-        return chunks
-    }
-
-    static parseChunkToInt(intBytes: Buffer, minByteLen: number, maxByteLen: number, raise_on_Null = false) {
-        // # Parse data as unsigned-big-endian encoded integer.
-        // # For empty data different possibilities may occur:
-        // #      minByteLen <= 0 : return 0
-        // #      raise_on_Null == False and minByteLen > 0: return None
-        // #      raise_on_Null == True and minByteLen > 0:  raise SlpInvalidOutputMessage
-        if(intBytes.length >= minByteLen && intBytes.length <= maxByteLen)
-            return intBytes.readUIntBE(0, intBytes.length)
-        if(intBytes.length === 0 && !raise_on_Null)
-            return null;
-        throw Error('Field has wrong length');
-    }
-
-    static parseSlpOutputScript(outputScript: Buffer): SlpTransactionDetails {
-        let slpMsg = <SlpTransactionDetails>{};
-        let chunks: (Buffer|null)[];
+        // console.log(chunks);
+        return chunks;
+    }
+
+    public static parseSlpOutputScript(outputScript: Buffer): SlpTransactionDetails {
+        const slpMsg = {} as SlpTransactionDetails;
+        let chunks: Array<Buffer|null>;
         try {
             chunks = this.parseOpReturnToChunks(outputScript);
-        } catch(e) {
-            throw Error('Bad OP_RETURN');
-        }
-        if(chunks.length === 0)
-            throw Error('Empty OP_RETURN');
-        if(!chunks[0])
-            throw Error("Not SLP")
-        if(!chunks[0]!.equals(Buffer.from(this.lokadIdHex, 'hex')))
-            throw Error('Not SLP');
-        if(chunks.length === 1)
+        } catch (e) {
+            throw Error("Bad OP_RETURN");
+        }
+        if (chunks.length === 0) {
+            throw Error("Empty OP_RETURN");
+        }
+        if (!chunks[0]) {
+            throw Error("Not SLP");
+        }
+        if (!chunks[0]!.equals(Buffer.from(this.lokadIdHex, "hex"))) {
+            throw Error("Not SLP");
+        }
+        if (chunks.length === 1) {
             throw Error("Missing token versionType");
+        }
         // # check if the token version is supported
-        if(!chunks[1])
-            throw Error("Bad versionType buffer")
-        slpMsg.versionType = <SlpVersionType>Slp.parseChunkToInt(chunks[1]!, 1, 2, true);
-        let supportedTypes = [   
-                SlpVersionType.TokenVersionType1, 
+        if (!chunks[1]) {
+            throw Error("Bad versionType buffer");
+        }
+        slpMsg.versionType = (Slp.parseChunkToInt(chunks[1]!, 1, 2, true) as SlpVersionType);
+        const supportedTypes = [
+                SlpVersionType.TokenVersionType1,
                 SlpVersionType.TokenVersionType1_NFT_Parent,
                 SlpVersionType.TokenVersionType1_NFT_Child ];
-        if(!supportedTypes.includes(slpMsg.versionType))
-            throw Error('Unsupported token type: ' + slpMsg.versionType);
-        if(chunks.length === 2)
-            throw Error('Missing SLP transaction type');
+        if (!supportedTypes.includes(slpMsg.versionType)) {
+            throw Error("Unsupported token type: " + slpMsg.versionType);
+        }
+        if (chunks.length === 2) {
+            throw Error("Missing SLP transaction type");
+        }
         try {
-            let msgType: string = chunks[2]!.toString('ascii')
-            slpMsg.transactionType = SlpTransactionType[msgType as keyof typeof SlpTransactionType]
-        } catch(_){
-            throw Error('Bad transaction type');
-        }
-        if(slpMsg.transactionType === SlpTransactionType.GENESIS) {
-            if(chunks.length !== 10)
-                throw Error('GENESIS with incorrect number of parameters');
-            slpMsg.symbol = chunks[3] ? chunks[3]!.toString('utf8') : '';
-            slpMsg.name = chunks[4] ? chunks[4]!.toString('utf8') : '';
-            slpMsg.documentUri = chunks[5] ? chunks[5]!.toString('utf8') : '';
+            const msgType: string = chunks[2]!.toString("latin1");
+            slpMsg.transactionType = SlpTransactionType[msgType as keyof typeof SlpTransactionType];
+        } catch (_) {
+            throw Error("Bad transaction type");
+        }
... (diff truncated)
```
