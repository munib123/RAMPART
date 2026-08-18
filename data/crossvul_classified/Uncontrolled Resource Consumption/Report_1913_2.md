# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 1913_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1913_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 24-64 of the vulnerable file.

	baseKeyCommitted = byte(0x00)
	baseKeyPending   = byte(0x01)
)

// Pool maintains a pool of valid evidence to be broadcasted and committed
type Pool struct {
	logger log.Logger

	evidenceStore dbm.DB
	evidenceList  *clist.CList // concurrent linked-list of evidence
	evidenceSize  uint32       // amount of pending evidence

	// needed to load validators to verify evidence
	stateDB sm.Store
	// needed to load headers and commits to verify evidence
	blockStore BlockStore

	mtx sync.Mutex
	// latest state
	state sm.State
	// evidence from consensus if buffered to this slice, awaiting until the next height
	// before being flushed to the pool. This prevents broadcasting and proposing of
	// evidence before the height with which the evidence happened is finished.
	consensusBuffer []types.Evidence

	pruningHeight int64
	pruningTime   time.Time
}

// NewPool creates an evidence pool. If using an existing evidence store,
// it will add all pending evidence to the concurrent list.
func NewPool(evidenceDB dbm.DB, stateDB sm.Store, blockStore BlockStore) (*Pool, error) {

	state, err := stateDB.Load()
	if err != nil {
		return nil, fmt.Errorf("cannot load state: %w", err)
	}

	pool := &Pool{
		stateDB:         stateDB,
		blockStore:      blockStore,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,10 +41,10 @@
 	mtx sync.Mutex
 	// latest state
 	state sm.State
-	// evidence from consensus if buffered to this slice, awaiting until the next height
+	// evidence from consensus is buffered to this slice, awaiting until the next height
 	// before being flushed to the pool. This prevents broadcasting and proposing of
 	// evidence before the height with which the evidence happened is finished.
-	consensusBuffer []types.Evidence
+	consensusBuffer []duplicateVoteSet
 
 	pruningHeight int64
 	pruningTime   time.Time
@@ -66,7 +66,7 @@
 		logger:          log.NewNopLogger(),
 		evidenceStore:   evidenceDB,
 		evidenceList:    clist.New(),
-		consensusBuffer: make([]types.Evidence, 0),
+		consensusBuffer: make([]duplicateVoteSet, 0),
 	}
 
 	// if pending evidence already in db, in event of prior failure, then check for expiration,
@@ -96,31 +96,30 @@
 	return evidence, size
 }
 
-// Update pulls the latest state to be used for expiration and evidence params and then prunes all expired evidence
+// Update takes both the new state and the evidence committed at that height and performs
+// the following operations:
+// 1. Take any conflicting votes from consensus and use the state's LastBlockTime to form
+//    DuplicateVoteEvidence and add it to the pool.
+// 2. Update the pool's state which contains evidence params relating to expiry.
+// 3. Moves pending evidence that has now been committed into the committed pool.
+// 4. Removes any expired evidence based on both height and time.
 func (evpool *Pool) Update(state sm.State, ev types.EvidenceList) {
 	// sanity check
 	if state.LastBlockHeight <= evpool.state.LastBlockHeight {
 		panic(fmt.Sprintf(
-			"Failed EvidencePool.Update new state height is less than or equal to previous state height: %d <= %d",
+			"failed EvidencePool.Update new state height is less than or equal to previous state height: %d <= %d",
 			state.LastBlockHeight,
 			evpool.state.LastBlockHeight,
 		))
 	}
-	evpool.logger.Info("Updating evidence pool", "last_block_height", state.LastBlockHeight,
+	evpool.logger.Debug("Updating evidence pool", "last_block_height", state.LastBlockHeight,
 		"last_block_time", state.LastBlockTime)
 
-	evpool.logger.Info(
-		"updating evidence pool",
-		"last_block_height", state.LastBlockHeight,
-		"last_block_time", state.LastBlockTime,
-	)
-
-	evpool.mtx.Lock()
-	// flush awaiting evidence from consensus into pool
-	evpool.flushConsensusBuffer()
+	// flush conflicting vote pairs from the buffer, producing DuplicateVoteEvidence and
+	// adding it to the pool
+	evpool.processConsensusBuffer(state)
 	// update state
-	evpool.state = state
-	evpool.mtx.Unlock()
+	evpool.updateState(state)
 
 	// move committed evidence out from the pending pool and into the committed pool
 	evpool.markEvidenceAsCommitted(ev)
@@ -138,7 +137,7 @@
 
 	// We have already verified this piece of evidence - no need to do it again
 	if evpool.isPending(ev) {
-		evpool.logger.Info("Evidence already pending, ignoring this one", "ev", ev)
+		evpool.logger.Debug("Evidence already pending, ignoring this one", "ev", ev)
 		return nil
 	}
 
@@ -169,25 +168,22 @@
 	return nil
 }
 
-// AddEvidenceFromConsensus should be exposed only to the consensus reactor so it can add evidence
-// to the pool directly without the need for verification.
-func (evpool *Pool) AddEvidenceFromConsensus(ev types.Evidence) error {
-
-	// we already have this evidence, log this but don't return an error.
-	if evpool.isPending(ev) {
-		evpool.logger.Info("Evidence already pending, ignoring this one", "ev", ev)
-		return nil
-	}
-
-	// add evidence to a buffer which will pass the evidence to the pool at the following height.
-	// This avoids the issue of some nodes verifying and proposing evidence at a height where the
-	// block hasn't been committed on cause others to potentially fail.
+// ReportConflictingVotes takes two conflicting votes and forms duplicate vote evidence,
+// adding it eventually to the evidence pool.
+//
+// Duplicate vote attacks happen before the block is committed and the timestamp is
+// finalized, thus the evidence pool holds these votes in a buffer, forming the
+// evidence from them once consensus at that height has been reached and `Update()` with
+// the new state called.
+//
+// Votes are not verified.
+func (evpool *Pool) ReportConflictingVotes(voteA, voteB *types.Vote) {
 	evpool.mtx.Lock()
 	defer evpool.mtx.Unlock()
-	evpool.consensusBuffer = append(evpool.consensusBuffer, ev)
-	evpool.logger.Info("received new evidence of byzantine behavior from consensus", "evidence", ev)
-
-	return nil
+	evpool.consensusBuffer = append(evpool.consensusBuffer, duplicateVoteSet{
+		VoteA: voteA,
+		VoteB: voteB,
+	})
 }
 
 // CheckEvidence takes an array of evidence from a block and verifies all the evidence there.
@@ -208,7 +204,7 @@
 
 			err := evpool.verify(ev)
 			if err != nil {
-				return &types.ErrInvalidEvidence{Evidence: ev, Reason: err}
+				return err
 			}
 
 			if err := evpool.addPendingEvidence(ev); err != nil {
@@ -380,7 +376,7 @@
 		evpool.logger.Error("Unable to delete pending evidence", "err", err)
 	} else {
 		atomic.AddUint32(&evpool.evidenceSize, ^uint32(0))
-		evpool.logger.Info("Deleted pending evidence", "evidence", evidence)
+		evpool.logger.Debug("Deleted pending evidence", "evidence", evidence)
 	}
 }
 
@@ -507,19 +503,91 @@
 	}
 }
 
-// flushConsensusBuffer moves the evidence produced from consensus into the evidence pool
-// and list so that it can be broadcasted and proposed
-func (evpool *Pool) flushConsensusBuffer() {
-	for _, ev := range evpool.consensusBuffer {
-		if err := evpool.addPendingEvidence(ev); err != nil {
+func (evpool *Pool) updateState(state sm.State) {
+	evpool.mtx.Lock()
+	defer evpool.mtx.Unlock()
+	evpool.state = state
+}
+
+// processConsensusBuffer converts all the duplicate votes witnessed from consensus
+// into DuplicateVoteEvidence. It sets the evidence timestamp to the block height
+// from the most recently committed block.
+// Evidence is then added to the pool so as to be ready to be broadcasted and proposed.
+func (evpool *Pool) processConsensusBuffer(state sm.State) {
+	evpool.mtx.Lock()
+	defer evpool.mtx.Unlock()
+	for _, voteSet := range evpool.consensusBuffer {
+
+		// Check the height of the conflicting votes and fetch the corresponding time and validator set
+		// to produce the valid evidence
+		var dve *types.DuplicateVoteEvidence
+		switch {
+		case voteSet.VoteA.Height == state.LastBlockHeight:
+			dve = types.NewDuplicateVoteEvidence(
+				voteSet.VoteA,
+				voteSet.VoteB,
+				state.LastBlockTime,
+				state.LastValidators,
+			)
+
+		case voteSet.VoteA.Height < state.LastBlockHeight:
+			valSet, err := evpool.stateDB.LoadValidators(voteSet.VoteA.Height)
+			if err != nil {
+				evpool.logger.Error("failed to load validator set for conflicting votes", "height",
+					voteSet.VoteA.Height, "err", err,
+				)
+				continue
+			}
+			blockMeta := evpool.blockStore.LoadBlockMeta(voteSet.VoteA.Height)
+			if blockMeta == nil {
+				evpool.logger.Error("failed to load block time for conflicting votes", "height", voteSet.VoteA.Height)
+				continue
+			}
+			dve = types.NewDuplicateVoteEvidence(
+				voteSet.VoteA,
+				voteSet.VoteB,
+				blockMeta.Header.Time,
+				valSet,
+			)
+
+		default:
+			// evidence pool shouldn't expect to get votes from consensus of a height that is above the current
+			// state. If this error is seen then perhaps consider keeping the votes in the buffer and retry
+			// in following heights
+			evpool.logger.Error("inbound duplicate votes from consensus are of a greater height than current state",
+				"duplicate vote height", voteSet.VoteA.Height,
+				"state.LastBlockHeight", state.LastBlockHeight)
+			continue
+		}
+
+		// check if we already have this evidence
+		if evpool.isPending(dve) {
+			evpool.logger.Debug("evidence already pending; ignoring", "evidence", dve)
+			continue
+		}
+
... (diff truncated)
```
