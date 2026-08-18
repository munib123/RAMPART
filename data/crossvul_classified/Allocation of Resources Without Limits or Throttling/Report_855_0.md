# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in go
**Pair ID:** 855_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `855_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```go
Lines 312-352 of the vulnerable file.

	if e != nil {
		err = NewProtocolException(e)
		return
	}
	kType = Type(k)
	v, e := p.ReadByte()
	if e != nil {
		err = NewProtocolException(e)
		return
	}
	vType = Type(v)
	size32, e := p.ReadI32()
	if e != nil {
		err = NewProtocolException(e)
		return
	}
	if size32 < 0 {
		err = invalidDataLength
		return
	}
	size = int(size32)
	return kType, vType, size, nil
}

func (p *BinaryProtocol) ReadMapEnd() error {
	return nil
}

func (p *BinaryProtocol) ReadListBegin() (elemType Type, size int, err error) {
	b, e := p.ReadByte()
	if e != nil {
		err = NewProtocolException(e)
		return
	}
	elemType = Type(b)
	size32, e := p.ReadI32()
	if e != nil {
		err = NewProtocolException(e)
		return
	}
	if size32 < 0 {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -329,6 +329,10 @@
 		err = invalidDataLength
 		return
 	}
+	if uint64(size32*2) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
+		err = invalidDataLength
+		return
+	}
 	size = int(size32)
 	return kType, vType, size, nil
 }
@@ -353,6 +357,10 @@
 		err = invalidDataLength
 		return
 	}
+	if uint64(size32) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
+		err = invalidDataLength
+		return
+	}
 	size = int(size32)
 
 	return
@@ -375,6 +383,10 @@
 		return
 	}
 	if size32 < 0 {
+		err = invalidDataLength
+		return
+	}
+	if uint64(size32) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
 		err = invalidDataLength
 		return
 	}
@@ -456,7 +468,7 @@
 	if size < 0 {
 		return nil, invalidDataLength
 	}
-	if uint64(size) > p.trans.RemainingBytes() {
+	if uint64(size) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
 		return nil, invalidDataLength
 	}
 
@@ -487,7 +499,7 @@
 	if size < 0 {
 		return "", nil
 	}
-	if uint64(size) > p.trans.RemainingBytes() {
+	if uint64(size) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
 		return "", invalidDataLength
 	}
 	var buf []byte
```
