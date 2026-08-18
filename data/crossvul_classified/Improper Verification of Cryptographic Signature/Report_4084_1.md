# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in go
**Pair ID:** 4084_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4084_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```go
Lines 532-574 of the vulnerable file.

	if voteSet == nil {
		return "nil-VoteSet"
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	_, _, frac := voteSet.sumTotalFrac()
	return fmt.Sprintf(`VoteSet{H:%v R:%v T:%v +2/3:%v(%v) %v %v}`,
		voteSet.height, voteSet.round, voteSet.signedMsgType, voteSet.maj23, frac, voteSet.votesBitArray, voteSet.peerMaj23s)
}

// return the power voted, the total, and the fraction
func (voteSet *VoteSet) sumTotalFrac() (int64, int64, float64) {
	voted, total := voteSet.sum, voteSet.valSet.TotalVotingPower()
	fracVoted := float64(voted) / float64(total)
	return voted, total, fracVoted
}

//--------------------------------------------------------------------------------
// Commit

// MakeCommit constructs a Commit from the VoteSet.
// Panics if the vote type is not PrecommitType or if
// there's no +2/3 votes for a single block.
func (voteSet *VoteSet) MakeCommit() *Commit {
	if voteSet.signedMsgType != tmproto.PrecommitType {
		panic("Cannot MakeCommit() unless VoteSet.Type is PrecommitType")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	// Make sure we have a 2/3 majority
	if voteSet.maj23 == nil {
		panic("Cannot MakeCommit() unless a blockhash has +2/3")
	}

	// For every validator, get the precommit
	commitSigs := make([]CommitSig, len(voteSet.votes))
	for i, v := range voteSet.votes {
		commitSigs[i] = v.CommitSig()
	}

	return NewCommit(voteSet.GetHeight(), voteSet.GetRound(), *voteSet.maj23, commitSigs)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -549,9 +549,11 @@
 //--------------------------------------------------------------------------------
 // Commit
 
-// MakeCommit constructs a Commit from the VoteSet.
-// Panics if the vote type is not PrecommitType or if
-// there's no +2/3 votes for a single block.
+// MakeCommit constructs a Commit from the VoteSet. It only includes precommits
+// for the block, which has 2/3+ majority, and nil.
+//
+// Panics if the vote type is not PrecommitType or if there's no +2/3 votes for
+// a single block.
 func (voteSet *VoteSet) MakeCommit() *Commit {
 	if voteSet.signedMsgType != tmproto.PrecommitType {
 		panic("Cannot MakeCommit() unless VoteSet.Type is PrecommitType")
@@ -567,7 +569,12 @@
 	// For every validator, get the precommit
 	commitSigs := make([]CommitSig, len(voteSet.votes))
 	for i, v := range voteSet.votes {
-		commitSigs[i] = v.CommitSig()
+		commitSig := v.CommitSig()
+		// if block ID exists but doesn't match, exclude sig
+		if commitSig.ForBlock() && !v.BlockID.Equals(*voteSet.maj23) {
+			commitSig = NewCommitSigAbsent()
+		}
+		commitSigs[i] = commitSig
 	}
 
 	return NewCommit(voteSet.GetHeight(), voteSet.GetRound(), *voteSet.maj23, commitSigs)
```
