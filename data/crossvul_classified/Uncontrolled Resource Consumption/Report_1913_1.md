# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 1913_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1913_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 56-98 of the vulnerable file.


// internally generated messages which may update the state
type timeoutInfo struct {
	Duration time.Duration         `json:"duration"`
	Height   int64                 `json:"height"`
	Round    int32                 `json:"round"`
	Step     cstypes.RoundStepType `json:"step"`
}

func (ti *timeoutInfo) String() string {
	return fmt.Sprintf("%v ; %d/%d %v", ti.Duration, ti.Height, ti.Round, ti.Step)
}

// interface to the mempool
type txNotifier interface {
	TxsAvailable() <-chan struct{}
}

// interface to the evidence pool
type evidencePool interface {
	// Adds consensus based evidence to the evidence pool. This function differs to
	// AddEvidence by bypassing verification and adding it immediately to the pool
	AddEvidenceFromConsensus(types.Evidence) error
}

// State handles execution of the consensus algorithm.
// It processes votes and proposals, and upon reaching agreement,
// commits blocks to the chain and executes them against the application.
// The internal state machine receives input from peers, the internal validator, and from a timer.
type State struct {
	service.BaseService

	// config details
	config        *cfg.ConsensusConfig
	privValidator types.PrivValidator // for signing votes

	// store blocks and commits
	blockStore sm.BlockStore

	// create and execute blocks
	blockExec *sm.BlockExecutor

	// notify us if txs are available
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,9 +73,8 @@
 
 // interface to the evidence pool
 type evidencePool interface {
-	// Adds consensus based evidence to the evidence pool. This function differs to
-	// AddEvidence by bypassing verification and adding it immediately to the pool
-	AddEvidenceFromConsensus(types.Evidence) error
+	// reports conflicting votes to the evidence pool to be processed into evidence
+	ReportConflictingVotes(voteA, voteB *types.Vote)
 }
 
 // State handles execution of the consensus algorithm.
@@ -1865,21 +1864,12 @@
 					vote.Type)
 				return added, err
 			}
-			var timestamp time.Time
-			if voteErr.VoteA.Height == cs.state.InitialHeight {
-				timestamp = cs.state.LastBlockTime // genesis time
-			} else {
-				timestamp = sm.MedianTime(cs.LastCommit.MakeCommit(), cs.LastValidators)
-			}
-			// form duplicate vote evidence from the conflicting votes and send it across to the
-			// evidence pool
-			ev := types.NewDuplicateVoteEvidence(voteErr.VoteA, voteErr.VoteB, timestamp, cs.Validators)
-			evidenceErr := cs.evpool.AddEvidenceFromConsensus(ev)
-			if evidenceErr != nil {
-				cs.Logger.Error("Failed to add evidence to the evidence pool", "err", evidenceErr)
-			} else {
-				cs.Logger.Debug("Added evidence to the evidence pool", "ev", ev)
-			}
+			// report conflicting votes to the evidence pool
+			cs.evpool.ReportConflictingVotes(voteErr.VoteA, voteErr.VoteB)
+			cs.Logger.Info("Found and sent conflicting votes to the evidence pool",
+				"VoteA", voteErr.VoteA,
+				"VoteB", voteErr.VoteB,
+			)
 			return added, err
 		} else if err == types.ErrVoteNonDeterministicSignature {
 			cs.Logger.Debug("Vote has non-deterministic signature", "err", err)
```
