# CrossVul Fix Pair: Integer Overflow or Wraparound in go
**Pair ID:** 408_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `408_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```go
Lines 1204-1244 of the vulnerable file.

	}
}

func (net *Network) checkTopicRegister(data *topicRegister) (*pong, error) {
	var pongpkt ingressPacket
	if err := decodePacket(data.Pong, &pongpkt); err != nil {
		return nil, err
	}
	if pongpkt.ev != pongPacket {
		return nil, errors.New("is not pong packet")
	}
	if pongpkt.remoteID != net.tab.self.ID {
		return nil, errors.New("not signed by us")
	}
	// check that we previously authorised all topics
	// that the other side is trying to register.
	hash, _, _ := wireHash(data.Topics)
	if hash != pongpkt.data.(*pong).TopicHash {
		return nil, errors.New("topic hash mismatch")
	}
	if data.Idx < 0 || int(data.Idx) >= len(data.Topics) {
		return nil, errors.New("topic index out of range")
	}
	return pongpkt.data.(*pong), nil
}

func wireHash(x interface{}) (h common.Hash, n int, err error) {
	hw := sha3.New256()
	wire.WriteBinary(x, hw, &n, &err)
	hw.Sum(h[:0])
	return h, n, err
}

func (net *Network) handleNeighboursPacket(n *Node, pkt *ingressPacket) error {
	if n.pendingNeighbours == nil {
		return errNoQuery
	}
	net.abortTimedEvent(n, neighboursTimeout)

	req := pkt.data.(*neighbors)
	nodes := make([]*Node, len(req.Nodes))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1221,7 +1221,7 @@
 	if hash != pongpkt.data.(*pong).TopicHash {
 		return nil, errors.New("topic hash mismatch")
 	}
-	if data.Idx < 0 || int(data.Idx) >= len(data.Topics) {
+	if int(data.Idx) < 0 || int(data.Idx) >= len(data.Topics) {
 		return nil, errors.New("topic index out of range")
 	}
 	return pongpkt.data.(*pong), nil
```
