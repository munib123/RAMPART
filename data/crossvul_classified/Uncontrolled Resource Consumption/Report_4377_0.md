# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 4377_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4377_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 593-633 of the vulnerable file.

		}

	case GetProofsV2Msg:
		p.Log().Trace("Received les/2 proofs request")
		if metrics.EnabledExpensive {
			miscInTrieProofPacketsMeter.Mark(1)
			miscInTrieProofTrafficMeter.Mark(int64(msg.Size))
		}
		var req struct {
			ReqID uint64
			Reqs  []ProofReq
		}
		if err := msg.Decode(&req); err != nil {
			clientErrorMeter.Mark(1)
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			lastBHash common.Hash
			root      common.Hash
		)
		reqCnt := len(req.Reqs)
		if accept(req.ReqID, uint64(reqCnt), MaxProofsFetch) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				nodes := light.NewNodeSet()

				for i, request := range req.Reqs {
					if i != 0 && !task.waitOrStop() {
						sendResponse(req.ReqID, 0, nil, task.servingTime)
						return
					}
					// Look up the root hash belonging to the request
					var (
						header *types.Header
						trie   state.Trie
					)
					if request.BHash != lastBHash {
						root, lastBHash = common.Hash{}, request.BHash

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -610,6 +610,7 @@
 		var (
 			lastBHash common.Hash
 			root      common.Hash
+			header    *types.Header
 		)
 		reqCnt := len(req.Reqs)
 		if accept(req.ReqID, uint64(reqCnt), MaxProofsFetch) {
@@ -624,10 +625,6 @@
 						return
 					}
 					// Look up the root hash belonging to the request
-					var (
-						header *types.Header
-						trie   state.Trie
-					)
 					if request.BHash != lastBHash {
 						root, lastBHash = common.Hash{}, request.BHash
 
@@ -654,6 +651,7 @@
 					// Open the account or storage trie for the request
 					statedb := h.blockchain.StateCache()
 
+					var trie state.Trie
 					switch len(request.AccKey) {
 					case 0:
 						// No account key specified, open an account trie
```
